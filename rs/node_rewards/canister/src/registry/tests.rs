use crate::registry::RegistryClient;
use chrono::{DateTime, NaiveDateTime, Utc};
use ic_base_types::{NodeId, PrincipalId};
use ic_nervous_system_canisters::registry::RegistryCanister;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_canister_client::{
    RegistryDataStableMemory, StableCanisterRegistryClient, StorableRegistryKey,
    StorableRegistryValue,
};
use ic_registry_keys::{
    DATA_CENTER_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_RECORD_KEY_PREFIX,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use rewards_calculation::rewards_calculator_results::DayUTC;
use rewards_calculation::types::ProviderRewardableNodes;
use std::cell::RefCell;
use std::sync::Arc;

pub type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static STATE: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>> = RefCell::new({
        let mgr = MemoryManager::init(DefaultMemoryImpl::default());
        StableBTreeMap::init(mgr.get(MemoryId::new(0)))
    });
}

pub struct DummyStore;

impl RegistryDataStableMemory for DummyStore {
    fn with_registry_map<R>(
        f: impl FnOnce(&StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R {
        STATE.with_borrow(f)
    }

    fn with_registry_map_mut<R>(
        f: impl FnOnce(&mut StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>) -> R,
    ) -> R {
        STATE.with_borrow_mut(f)
    }
}

pub fn dt_to_timestamp_nanos(datetime_str: &str) -> u64 {
    let dt = format!("{} 00:00:00", datetime_str);
    let naive =
        NaiveDateTime::parse_from_str(&dt, "%Y-%m-%d %H:%M:%S").expect("Invalid date format");
    let datetime: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, Utc);
    datetime.timestamp_nanos_opt().unwrap() as u64
}

pub fn add_record_helper(
    key: &str,
    version: u64,
    value: Option<impl ::prost::Message>,
    datetime_str: &str,
) {
    STATE.with_borrow_mut(|map| {
        map.insert(
            StorableRegistryKey::new(
                key.to_string(),
                version,
                dt_to_timestamp_nanos(datetime_str),
            ),
            StorableRegistryValue(value.map(|v| v.encode_to_vec())),
        );
    });
}

fn add_dummy_data() {
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

    let dc_1_id = "X".to_string();
    let node_1_id = 1;
    let node_2_id = 2;
    let node_3_id = 3;

    let no_1_id = 10;
    let np_1_id = 20;

    let (no_1_k, no_1_v) = generate_node_operator_key_value(no_1_id, np_1_id, dc_1_id.clone());
    let (dc_1_k, dc_1_v) = generate_dc_key_value(dc_1_id);
    let (node_1_k, node_1_v) = generate_node_key_value(node_1_id, NodeRewardType::Type0, no_1_id);
    let (node_2_k, node_2_v) = generate_node_key_value(node_2_id, NodeRewardType::Type1, no_1_id);
    let (node_3_k, node_3_v) = generate_node_key_value(node_3_id, NodeRewardType::Type2, no_1_id);

    add_record_helper(&no_1_k, 39650, Some(no_1_v), "2025-07-01");
    add_record_helper(&dc_1_k, 39652, Some(dc_1_v), "2025-07-02");
    add_record_helper(&node_1_k, 39662, Some(node_1_v), "2025-07-03");
    add_record_helper(&node_2_k, 39664, Some(node_2_v), "2025-07-04");
    add_record_helper(&node_1_k, 39666, None::<NodeRecord>, "2025-07-08");
    add_record_helper(&node_3_k, 39667, Some(node_3_v), "2025-07-11");
}

fn client_for_tests() -> RegistryClient<DummyStore> {
    add_dummy_data();

    RegistryClient {
        store: Arc::new(StableCanisterRegistryClient::<DummyStore>::new(Arc::new(
            RegistryCanister::new(),
        ))),
    }
}

fn node_rewardable_days(rewardable_nodes: &ProviderRewardableNodes, node_id: u64) -> Vec<DayUTC> {
    let node_id = NodeId::from(PrincipalId::new_node_test_id(node_id));

    rewardable_nodes
        .rewardable_nodes
        .iter()
        .find(|n| n.node_id == node_id)
        .unwrap_or_else(|| panic!("Node {} should be present", node_id))
        .clone()
        .rewardable_days
}

#[test]
fn test_rewardable_nodes_deleted_nodes() {
    let client = client_for_tests();

    // Define the range for which we want to check rewardable nodes.
    // This is *after* node_1 was deleted.
    let from = dt_to_timestamp_nanos("2025-07-12");
    let to = dt_to_timestamp_nanos("2025-07-14");

    let mut rewardables = client
        .get_rewardable_nodes_per_provider(from.into(), to.into())
        .expect("Failed to fetch rewardable nodes");

    let np_1_id = PrincipalId::new_user_test_id(20);
    let np_1_rewardables = rewardables
        .remove(&np_1_id)
        .expect("No rewardables found for node provider");

    // Node 1 was deleted before this period, so it should NOT be present.
    assert!(
        !np_1_rewardables
            .rewardable_nodes
            .iter()
            .any(|n| n.node_id == NodeId::from(PrincipalId::new_node_test_id(1))),
        "Node 1 should not be rewardable after it was deleted"
    );

    // Node 2 and 3 should be rewardable in this period.
    let node_2_rewardable_days = node_rewardable_days(&np_1_rewardables, 2);

    assert_eq!(node_2_rewardable_days.first(), Some(&from.into()));
    assert_eq!(node_2_rewardable_days.last(), Some(&to.into()));

    let node_3_rewardable_days = node_rewardable_days(&np_1_rewardables, 3);

    assert_eq!(node_3_rewardable_days.first(), Some(&from.into()));
    assert_eq!(node_3_rewardable_days.last(), Some(&to.into()));
}

#[test]
fn test_rewardable_nodes_rewardables_till_deleted() {
    let client = client_for_tests();

    // Define a time range that spans:
    // - The active time of node_1 (until deletion on 2025-07-08),
    // - Node_2's full active range,
    // - Node_3's creation (on 2025-07-11).
    let from = dt_to_timestamp_nanos("2025-07-03");
    let to = dt_to_timestamp_nanos("2025-07-12");

    let mut rewardables = client
        .get_rewardable_nodes_per_provider(from.into(), to.into())
        .expect("Failed to fetch rewardable nodes");

    let np_1_id = PrincipalId::new_user_test_id(20);
    let np_1_rewardables = rewardables
        .remove(&np_1_id)
        .expect("No rewardables found for node provider");

    // Node 1 was deleted on 2025-07-08, so its rewardable period ends there.
    let node_1_rewardable_days = node_rewardable_days(&np_1_rewardables, 1);

    assert_eq!(node_1_rewardable_days.first(), Some(&from.into()));
    assert_eq!(
        node_1_rewardable_days.last(),
        Some(&dt_to_timestamp_nanos("2025-07-08").into())
    );

    // Node 2 is active throughout the whole range.
    let node_2_rewardable_days = node_rewardable_days(&np_1_rewardables, 2);

    assert_eq!(
        node_2_rewardable_days.first(),
        Some(&dt_to_timestamp_nanos("2025-07-04").into())
    );
    assert_eq!(node_2_rewardable_days.last(), Some(&to.into()));

    // Node 3 became active on 2025-07-11.
    let node_3_rewardable_days = node_rewardable_days(&np_1_rewardables, 3);

    assert_eq!(
        node_3_rewardable_days.first(),
        Some(&dt_to_timestamp_nanos("2025-07-11").into())
    );
    assert_eq!(node_3_rewardable_days.last(), Some(&to.into()));
}

#[test]
fn test_rewardable_nodes_node_appears_mid_range() {
    let client = client_for_tests();

    // Range spans before and after node_3 is created on 2025-07-11.
    let from = dt_to_timestamp_nanos("2025-07-10");
    let to = dt_to_timestamp_nanos("2025-07-14");

    let mut rewardables = client
        .get_rewardable_nodes_per_provider(from.into(), to.into())
        .expect("Failed to fetch rewardables");

    let np_1_id = PrincipalId::new_user_test_id(20);
    let np_1_rewardables = rewardables
        .remove(&np_1_id)
        .expect("Expected rewardables for node provider");

    let node_3_rewardable_days = node_rewardable_days(&np_1_rewardables, 3);

    assert_eq!(
        node_3_rewardable_days.first(),
        Some(&dt_to_timestamp_nanos("2025-07-11").into()),
        "Node 3 should become rewardable on 2025-07-11"
    );
    assert_eq!(
        node_3_rewardable_days.last(),
        Some(&to.into()),
        "Node 3 should remain rewardable until end of the range"
    );
}

#[test]
fn test_node_re_registered_after_deletion() {
    let node_1_id = 1;
    let no_1_id = 10;

    // Re-register node_1 after it was deleted
    let node_id = PrincipalId::new_node_test_id(node_1_id);
    let node_key = format!("{}{}", NODE_RECORD_KEY_PREFIX, node_id);
    let node_record = NodeRecord {
        node_reward_type: Some(NodeRewardType::Type0 as i32),
        node_operator_id: PrincipalId::new_user_test_id(no_1_id).to_vec(),
        ..NodeRecord::default()
    };

    add_record_helper(&node_key, 39668, Some(node_record), "2025-07-10");

    let client = client_for_tests();

    // Range that includes both the deletion and re-registration periods
    let from = dt_to_timestamp_nanos("2025-07-07");
    let to = dt_to_timestamp_nanos("2025-07-12");

    let mut rewardables = client
        .get_rewardable_nodes_per_provider(from.into(), to.into())
        .expect("Failed to fetch rewardables");

    let np_1_id = PrincipalId::new_user_test_id(20);
    let np_1_rewardables = rewardables
        .remove(&np_1_id)
        .expect("No rewardables for node provider");

    let node_1_rewardable_days = node_rewardable_days(&np_1_rewardables, node_1_id);

    let expected_days: Vec<DayUTC> = vec![
        dt_to_timestamp_nanos("2025-07-07").into(),
        dt_to_timestamp_nanos("2025-07-08").into(),
        // On 2025-07-08, node_1 was deleted, so it should not be rewardable the 2025-07-09.
        dt_to_timestamp_nanos("2025-07-10").into(),
        dt_to_timestamp_nanos("2025-07-11").into(),
        dt_to_timestamp_nanos("2025-07-12").into(),
    ];

    assert_eq!(node_1_rewardable_days, expected_days);
}
