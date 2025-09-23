use crate::canister::NodeRewardsCanister;
use crate::canister::test::test_utils::{CANISTER_TEST, setup_thread_local_canister_for_test};
use futures_util::FutureExt;
use ic_base_types::{NodeId, PrincipalId};
use ic_nervous_system_canisters::registry::fake::FakeRegistry;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::{
    DATA_CENTER_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_RECORD_KEY_PREFIX,
};
use rewards_calculation::performance_based_algorithm::DataProvider;
use rewards_calculation::types::{DayUtc, RewardableNode};
use std::sync::Arc;

fn generate_node_key_value(
    id: u64,
    node_type: NodeRewardType,
    node_operator_id: u64,
) -> (String, NodeRecord) {
    let value = NodeRecord {
        node_reward_type: Some(node_type as i32),
        node_operator_id: PrincipalId::new_user_test_id(node_operator_id).to_vec(),
        ..NodeRecord::default()
    };
    let key = format!(
        "{}{}",
        NODE_RECORD_KEY_PREFIX,
        PrincipalId::new_node_test_id(id)
    );

    (key, value)
}
fn generate_node_operator_key_value(
    id: u64,
    node_provider_id: u64,
    dc_id: String,
) -> (String, NodeOperatorRecord) {
    let principal_id = PrincipalId::new_user_test_id(id);
    let node_provider = PrincipalId::new_user_test_id(node_provider_id);
    let value = NodeOperatorRecord {
        node_operator_principal_id: principal_id.to_vec(),
        node_provider_principal_id: node_provider.to_vec(),
        dc_id,
        ..NodeOperatorRecord::default()
    };
    let key = format!("{}{}", NODE_OPERATOR_RECORD_KEY_PREFIX, principal_id);

    (key, value)
}

fn generate_dc_key_value(dc_id: String) -> (String, DataCenterRecord) {
    let value = DataCenterRecord {
        id: dc_id.clone(),
        region: "A".to_string(),
        ..DataCenterRecord::default()
    };
    let key = format!("{}{}", DATA_CENTER_KEY_PREFIX, dc_id);

    (key, value)
}

pub fn add_record_helper(
    fake_registry: Arc<FakeRegistry>,
    key: &str,
    version: u64,
    value: Option<impl ::prost::Message>,
    datetime_str: &str,
) {
    let ts = DayUtc::try_from(datetime_str).unwrap();
    add_record_helper_ts(
        fake_registry,
        key,
        version,
        value,
        ts.unix_ts_at_day_end_nanoseconds(),
    );
}
pub fn add_record_helper_ts(
    fake_registry: Arc<FakeRegistry>,
    key: &str,
    version: u64,
    value: Option<impl ::prost::Message>,
    ts: u64,
) {
    fake_registry.set_value_at_version_with_timestamp(
        key,
        version,
        ts,
        value.map(|v| v.encode_to_vec()),
    );
}

fn add_dummy_data(fake_registry: Arc<FakeRegistry>) {
    let dc_1_id = "x".to_string();
    let dc_2_id = "y".to_string();
    let node_1_id = 1;
    let node_2_id = 2;
    let node_3_id = 3;
    let node_4_id = 4;
    let no_1_id = 10;
    let np_1_id = 20;
    let no_2_id = 30;
    let no_3_id = 40;
    let np_2_id = 50;

    let (no_1_k, no_1_v) = generate_node_operator_key_value(no_1_id, np_1_id, dc_1_id.clone());
    let (no_3_k, no_3_v) = generate_node_operator_key_value(no_3_id, np_2_id, dc_1_id.clone());
    let (dc_2_k, dc_2_v) = generate_dc_key_value(dc_2_id.clone());
    let (no_2_k, no_2_v) = generate_node_operator_key_value(no_2_id, np_1_id, dc_2_id);
    let (dc_1_k, dc_1_v) = generate_dc_key_value(dc_1_id);
    let (node_1_k, node_1_v) = generate_node_key_value(node_1_id, NodeRewardType::Type0, no_1_id);
    let (node_2_k, node_2_v) = generate_node_key_value(node_2_id, NodeRewardType::Type1, no_1_id);
    let (node_3_k, node_3_v) = generate_node_key_value(node_3_id, NodeRewardType::Type2, no_2_id);
    let (node_4_k, node_4_v) = generate_node_key_value(node_4_id, NodeRewardType::Type2, no_3_id);

    add_record_helper(
        fake_registry.clone(),
        &dc_2_k,
        1,
        Some(dc_2_v),
        "2025-07-01",
    );
    add_record_helper(
        fake_registry.clone(),
        &dc_1_k,
        2,
        Some(dc_1_v),
        "2025-07-02",
    );
    add_record_helper(
        fake_registry.clone(),
        &no_1_k,
        3,
        Some(no_1_v),
        "2025-07-02",
    );
    add_record_helper(
        fake_registry.clone(),
        &no_2_k,
        4,
        Some(no_2_v),
        "2025-07-02",
    );
    add_record_helper(
        fake_registry.clone(),
        &no_3_k,
        5,
        Some(no_3_v),
        "2025-07-02",
    );
    add_record_helper(
        fake_registry.clone(),
        &node_1_k,
        10,
        Some(node_1_v),
        "2025-07-03",
    );
    add_record_helper(
        fake_registry.clone(),
        &node_2_k,
        11,
        Some(node_2_v),
        "2025-07-04",
    );
    add_record_helper(
        fake_registry.clone(),
        &node_1_k,
        12,
        None::<NodeRecord>,
        "2025-07-08",
    );
    add_record_helper(
        fake_registry.clone(),
        &node_3_k,
        12,
        Some(node_3_v.clone()),
        "2025-07-11",
    );
    add_record_helper(
        fake_registry.clone(),
        &node_3_k,
        15,
        None::<NodeRecord>,
        "2025-07-13",
    );
    add_record_helper(
        fake_registry.clone(),
        &node_3_k,
        20,
        Some(node_3_v.clone()),
        "2025-07-15",
    );
    add_record_helper(
        fake_registry.clone(),
        &node_4_k,
        22,
        Some(node_4_v.clone()),
        "2025-07-16",
    );

    // Removed and re-added node_3 same day
    let ts_removed = DayUtc::try_from("2025-07-16")
        .unwrap()
        .unix_ts_at_day_start_nanoseconds()
        + 1;
    add_record_helper_ts(
        fake_registry.clone(),
        &node_3_k,
        30,
        None::<NodeRecord>,
        ts_removed,
    );
    let ts_readded = ts_removed + 1;
    add_record_helper_ts(fake_registry, &node_3_k, 33, Some(node_3_v), ts_readded);
}

fn contains_node(nodes: &[RewardableNode], node_num: u64) -> bool {
    nodes
        .iter()
        .any(|n| n.node_id == NodeId::from(PrincipalId::new_node_test_id(node_num)))
}
#[test]
fn test_rewardable_nodes_deleted_nodes() {
    let (registry, _) = setup_thread_local_canister_for_test();
    add_dummy_data(registry);
    NodeRewardsCanister::schedule_registry_sync(&CANISTER_TEST).now_or_never();
    let day1 = DayUtc::try_from("2025-07-12").unwrap();
    let day2 = DayUtc::try_from("2025-07-13").unwrap();
    let np_1_id = PrincipalId::new_user_test_id(20);
    let (rewardables_day1, rewardables_day2) = CANISTER_TEST.with_borrow(|canister| {
        canister
            .backfill_rewardable_nodes_single_day(&day1)
            .unwrap();
        canister
            .backfill_rewardable_nodes_single_day(&day2)
            .unwrap();
        let rewardables_day1 = canister
            .get_rewardable_nodes(&day1)
            .unwrap()
            .remove(&np_1_id)
            .unwrap();

        let rewardables_day2 = canister
            .get_rewardable_nodes(&day2)
            .unwrap()
            .remove(&np_1_id)
            .unwrap();
        (rewardables_day1, rewardables_day2)
    });

    // Day 1 expectations
    assert!(
        !contains_node(&rewardables_day1, 1),
        "Node 1 should not be rewardable after deletion"
    );
    assert!(
        contains_node(&rewardables_day1, 2),
        "Node 2 should be rewardable on day 1"
    );
    assert!(
        contains_node(&rewardables_day1, 3),
        "Node 3 should be rewardable on day 1"
    );

    // Day 2 expectations
    assert!(
        !contains_node(&rewardables_day2, 3),
        "Node 3 should NOT be rewardable on day 2 because it was removed"
    );
    assert!(
        contains_node(&rewardables_day2, 2),
        "Node 2 should be rewardable on day 2"
    );
}

#[test]
fn test_node_re_registered_after_deletion() {
    let node_1_id = 1;
    let no_1_id = 10;

    let node_id = PrincipalId::new_node_test_id(node_1_id);
    let node_key = format!("{}{}", NODE_RECORD_KEY_PREFIX, node_id);
    let node_record = NodeRecord {
        node_reward_type: Some(NodeRewardType::Type0 as i32),
        node_operator_id: PrincipalId::new_user_test_id(no_1_id).to_vec(),
        ..NodeRecord::default()
    };
    let (registry, _) = setup_thread_local_canister_for_test();
    add_dummy_data(registry.clone());
    add_record_helper(registry, &node_key, 13, Some(node_record), "2025-07-11");
    NodeRewardsCanister::schedule_registry_sync(&CANISTER_TEST).now_or_never();

    let from = DayUtc::try_from("2025-07-07").unwrap();
    let to = DayUtc::try_from("2025-07-12").unwrap();
    let mut current_day = from;
    let expected_absent = [
        DayUtc::try_from("2025-07-08").unwrap(),
        DayUtc::try_from("2025-07-09").unwrap(),
        DayUtc::try_from("2025-07-10").unwrap(),
    ];

    while current_day <= to {
        let rewardables = CANISTER_TEST.with_borrow(|canister| {
            canister
                .backfill_rewardable_nodes_single_day(&current_day)
                .unwrap();

            canister
                .get_rewardable_nodes(&current_day)
                .unwrap()
                .remove(&PrincipalId::new_user_test_id(20))
                .unwrap()
        });

        if expected_absent.contains(&current_day) {
            assert!(
                !contains_node(&rewardables, 1),
                "Node 1 should not be rewardable after deletion"
            );
        } else {
            assert!(
                contains_node(&rewardables, 1),
                "Node 1 should be rewardable on day 1"
            );
        }

        current_day = current_day.next_day();
    }
}
