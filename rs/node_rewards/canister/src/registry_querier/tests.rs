use crate::registry_querier::RegistryQuerier;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_nervous_system_canisters::registry::RegistryCanister;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates, NodeRewardsTable};
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_canister_client::{
    RegistryDataStableMemory, StableCanisterRegistryClient, StorableRegistryKey,
    StorableRegistryValue, test_registry_data_stable_memory_impl,
};
use ic_registry_keys::{
    DATA_CENTER_KEY_PREFIX, NODE_OPERATOR_RECORD_KEY_PREFIX, NODE_RECORD_KEY_PREFIX,
    NODE_REWARDS_TABLE_KEY, make_subnet_list_record_key,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use maplit::btreemap;
use rewards_calculation::types::{DayUtc, RewardPeriod, RewardableNode};
use std::cell::RefCell;
use std::sync::Arc;

pub type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static STATE: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>> = RefCell::new({
        let mgr = MemoryManager::init(DefaultMemoryImpl::default());
        StableBTreeMap::init(mgr.get(MemoryId::new(0)))
    });

    static REGISTRY_STORE: Arc<StableCanisterRegistryClient<DummyState>> = {
        let store = StableCanisterRegistryClient::<DummyState>::new(
            Arc::new(RegistryCanister::new()));
        Arc::new(store)
    };
}

test_registry_data_stable_memory_impl!(DummyState, STATE);

fn add_record_helper(
    key: &str,
    version: u64,
    value: Option<impl ::prost::Message>,
    datetime_str: &str,
) {
    let ts = DayUtc::try_from(datetime_str).unwrap();
    add_record_helper_ts(key, version, value, ts.unix_ts_at_day_end());
}

fn add_record_helper_ts(key: &str, version: u64, value: Option<impl ::prost::Message>, ts: u64) {
    STATE.with_borrow_mut(|map| {
        map.insert(
            StorableRegistryKey::new(key.to_string(), version, ts),
            StorableRegistryValue(value.map(|v| v.encode_to_vec())),
        );
    });
}

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
    let key = format!("{NODE_OPERATOR_RECORD_KEY_PREFIX}{principal_id}");

    (key, value)
}

fn generate_dc_key_value(dc_id: String) -> (String, DataCenterRecord) {
    let value = DataCenterRecord {
        id: dc_id.clone(),
        region: "A".to_string(),
        ..DataCenterRecord::default()
    };
    let key = format!("{DATA_CENTER_KEY_PREFIX}{dc_id}");

    (key, value)
}

fn add_dummy_data() {
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

    add_record_helper(&dc_2_k, 39651, Some(dc_2_v), "2025-07-01");
    add_record_helper(&dc_1_k, 39652, Some(dc_1_v), "2025-07-02");
    add_record_helper(&no_1_k, 39653, Some(no_1_v), "2025-07-02");
    add_record_helper(&no_2_k, 39654, Some(no_2_v), "2025-07-02");
    add_record_helper(&no_3_k, 39655, Some(no_3_v), "2025-07-02");
    add_record_helper(&node_1_k, 39662, Some(node_1_v), "2025-07-03");
    add_record_helper(&node_2_k, 39664, Some(node_2_v), "2025-07-04");
    add_record_helper(&node_1_k, 39666, None::<NodeRecord>, "2025-07-08");
    add_record_helper(&node_3_k, 39667, Some(node_3_v.clone()), "2025-07-11");
    add_record_helper(&node_3_k, 39670, None::<NodeRecord>, "2025-07-13");
    add_record_helper(&node_3_k, 39675, Some(node_3_v.clone()), "2025-07-15");
    add_record_helper(&node_4_k, 39676, Some(node_4_v.clone()), "2025-07-16");

    // Removed and re-added node_3 same day
    let ts_removed = DayUtc::try_from("2025-07-16")
        .unwrap()
        .unix_ts_at_day_start()
        + 1;
    add_record_helper_ts(&node_3_k, 39676, None::<NodeRecord>, ts_removed);
    let ts_readded = ts_removed + 1;
    add_record_helper_ts(&node_3_k, 39677, Some(node_3_v), ts_readded);
}

fn client_for_tests() -> RegistryQuerier {
    add_dummy_data();
    let store = REGISTRY_STORE.with(|store| store.clone());

    RegistryQuerier {
        registry_client: store,
    }
}

fn node_rewardable_days(rewardable_nodes: &[RewardableNode], node_id: u64) -> Vec<DayUtc> {
    let node_id = NodeId::from(PrincipalId::new_node_test_id(node_id));

    rewardable_nodes
        .iter()
        .find(|n| n.node_id == node_id)
        .unwrap_or_else(|| panic!("Node {node_id} should be present"))
        .clone()
        .rewardable_days
}

#[test]
fn test_subnets_list_returns_expected_subnets() {
    let client = client_for_tests();
    let subnet_1: SubnetId = PrincipalId::new_subnet_test_id(1).into();
    let subnet_2: SubnetId = PrincipalId::new_subnet_test_id(2).into();

    let key = make_subnet_list_record_key();
    let version = 39670;
    let deleted_version = version + 1;
    let subnets_record = SubnetListRecord {
        subnets: vec![subnet_1.get().to_vec(), subnet_2.get().to_vec()],
    };
    add_record_helper(&key, version, Some(subnets_record), "2025-07-13");
    add_record_helper(
        &key,
        deleted_version,
        None::<SubnetListRecord>,
        "2025-07-13",
    );

    let got = client.subnets_list(version.into());

    let expected: Vec<SubnetId> = vec![subnet_1, subnet_2];

    assert_eq!(got, expected);

    let got = client.subnets_list(deleted_version.into());

    let expected: Vec<SubnetId> = vec![];

    assert_eq!(got, expected);
}

#[test]
fn test_get_rewards_table_returns_correct_record() {
    let client = client_for_tests();
    let version = 39670;

    let table = NodeRewardsTable {
        table: btreemap! {
            "REGION_A".to_string() => NodeRewardRates {
                rates: btreemap! {
                    NodeRewardType::Type1.to_string() => NodeRewardRate{
                        xdr_permyriad_per_node_per_month: 1000,
                        reward_coefficient_percent: None,
                    }
                },
            }
        },
    };

    add_record_helper(
        NODE_REWARDS_TABLE_KEY,
        version,
        Some(table.clone()),
        "2025-07-13",
    );

    let result = client.get_rewards_table(version.into());

    assert_eq!(result, table);
}

#[test]
fn test_nodes_in_registry_returns_expected_days() {
    let _client = client_for_tests();

    // Time range where:
    // - node_1 exists until 2025-07-07
    // - node_2 is always present
    // - node_3 appears on 2025-07-11
    let from = DayUtc::try_from("2025-07-03").unwrap();
    let to = DayUtc::try_from("2025-07-16").unwrap();
    let nodes_map = RegistryQuerier::nodes_in_registry_between::<DummyState>(from, to);

    let node_1_id = NodeId::from(PrincipalId::new_node_test_id(1));
    let node_2_id = NodeId::from(PrincipalId::new_node_test_id(2));
    let node_3_id = NodeId::from(PrincipalId::new_node_test_id(3));

    let (_, _, node_1_days) = &nodes_map[&node_1_id];
    let expected_node_1_days: Vec<DayUtc> = vec![
        DayUtc::try_from("2025-07-03").unwrap(),
        DayUtc::try_from("2025-07-04").unwrap(),
        DayUtc::try_from("2025-07-05").unwrap(),
        DayUtc::try_from("2025-07-06").unwrap(),
        DayUtc::try_from("2025-07-07").unwrap(),
    ];
    assert_eq!(node_1_days, &expected_node_1_days);

    let (_, _, node_2_days) = &nodes_map[&node_2_id];
    let expected_node_2_days: Vec<DayUtc> = vec![
        DayUtc::try_from("2025-07-04").unwrap(),
        DayUtc::try_from("2025-07-05").unwrap(),
        DayUtc::try_from("2025-07-06").unwrap(),
        DayUtc::try_from("2025-07-07").unwrap(),
        DayUtc::try_from("2025-07-08").unwrap(),
        DayUtc::try_from("2025-07-09").unwrap(),
        DayUtc::try_from("2025-07-10").unwrap(),
        DayUtc::try_from("2025-07-11").unwrap(),
        DayUtc::try_from("2025-07-12").unwrap(),
        DayUtc::try_from("2025-07-13").unwrap(),
        DayUtc::try_from("2025-07-14").unwrap(),
        DayUtc::try_from("2025-07-15").unwrap(),
        DayUtc::try_from("2025-07-16").unwrap(),
    ];
    assert_eq!(node_2_days, &expected_node_2_days);

    let (_, _, node_3_days) = &nodes_map[&node_3_id];
    let expected_node_3_days: Vec<DayUtc> = vec![
        DayUtc::try_from("2025-07-11").unwrap(),
        DayUtc::try_from("2025-07-12").unwrap(),
        // node_3 was deleted on 2025-07-13, so it should not be present on 2025-07-14
        DayUtc::try_from("2025-07-15").unwrap(),
        DayUtc::try_from("2025-07-16").unwrap(),
    ];
    assert_eq!(node_3_days, &expected_node_3_days);
}

#[test]
fn test_rewardable_nodes_deleted_nodes() {
    let _client = client_for_tests();
    // Define the range for which we want to check rewardable nodes.
    // This is *after* node_1 was deleted.
    let from = DayUtc::try_from("2025-07-12").unwrap();
    let to = DayUtc::try_from("2025-07-13").unwrap();
    let _reward_period = RewardPeriod::new(from, to).expect("Failed to create reward period");

    let mut rewardables = RegistryQuerier::get_rewardable_nodes_per_provider::<DummyState>(
        &*REGISTRY_STORE.with(|store| store.clone()),
        from,
        to,
        None,
    )
    .expect("Failed to fetch rewardable nodes");

    let np_1_id = PrincipalId::new_user_test_id(20);
    let np_1_rewardables = rewardables
        .remove(&np_1_id)
        .expect("No rewardables found for node provider");

    // Node 1 was deleted before this period, so it should NOT be present.
    assert!(
        !np_1_rewardables
            .iter()
            .any(|n| n.node_id == NodeId::from(PrincipalId::new_node_test_id(1))),
        "Node 1 should not be rewardable after it was deleted"
    );

    // Node 2 should be rewardable in this period.
    let node_2_rewardable_days = node_rewardable_days(&np_1_rewardables, 2);

    assert_eq!(node_2_rewardable_days.first(), Some(&from));
    assert_eq!(node_2_rewardable_days.last(), Some(&to));

    let node_3_rewardable_days = node_rewardable_days(&np_1_rewardables, 3);

    // Node 3 should be rewardable until 2025-07-12 because on 2025-07-13 got deleted.
    assert_eq!(node_3_rewardable_days.first(), Some(&from));
    assert_eq!(
        node_3_rewardable_days.last(),
        Some(&DayUtc::try_from("2025-07-12").unwrap())
    );
}

#[test]
fn test_rewardable_nodes_rewardables_till_deleted() {
    let _client = client_for_tests();

    // Define a time range that spans:
    // - The active time of node_1 (until deletion on 2025-07-08),
    // - Node_2's full active range,
    // - Node_3's creation (on 2025-07-11).
    let from = DayUtc::try_from("2025-07-03").unwrap();
    let to = DayUtc::try_from("2025-07-12").unwrap();
    let _reward_period = RewardPeriod::new(from, to).expect("Failed to create reward period");

    let mut rewardables = RegistryQuerier::get_rewardable_nodes_per_provider::<DummyState>(
        &*REGISTRY_STORE.with(|store| store.clone()),
        from,
        to,
        None,
    )
    .expect("Failed to fetch rewardable nodes");

    let np_1_id = PrincipalId::new_user_test_id(20);
    let np_1_rewardables = rewardables
        .remove(&np_1_id)
        .expect("No rewardables found for node provider");

    // Node 1 was deleted on 2025-07-08, so its rewardable period ends there.
    let node_1_rewardable_days = node_rewardable_days(&np_1_rewardables, 1);

    assert_eq!(node_1_rewardable_days.first(), Some(&from));
    assert_eq!(
        node_1_rewardable_days.last(),
        Some(&DayUtc::try_from("2025-07-07").unwrap())
    );

    // Node 2 is active throughout the whole range.
    let node_2_rewardable_days = node_rewardable_days(&np_1_rewardables, 2);

    assert_eq!(
        node_2_rewardable_days.first(),
        Some(&DayUtc::try_from("2025-07-04").unwrap())
    );
    assert_eq!(node_2_rewardable_days.last(), Some(&to));

    // Node 3 became active on 2025-07-11.
    let node_3_rewardable_days = node_rewardable_days(&np_1_rewardables, 3);

    assert_eq!(
        node_3_rewardable_days.first(),
        Some(&DayUtc::try_from("2025-07-11").unwrap())
    );
    assert_eq!(node_3_rewardable_days.last(), Some(&to));
}

#[test]
fn test_node_re_registered_after_deletion() {
    let node_1_id = 1;
    let no_1_id = 10;

    // Re-register node_1 after it was deleted
    let node_id = PrincipalId::new_node_test_id(node_1_id);
    let node_key = format!("{NODE_RECORD_KEY_PREFIX}{node_id}");
    let node_record = NodeRecord {
        node_reward_type: Some(NodeRewardType::Type0 as i32),
        node_operator_id: PrincipalId::new_user_test_id(no_1_id).to_vec(),
        ..NodeRecord::default()
    };

    add_record_helper(&node_key, 39668, Some(node_record), "2025-07-11");

    let _client = client_for_tests();

    // Range that includes both the deletion and re-registration periods
    let from = DayUtc::try_from("2025-07-07").unwrap();
    let to = DayUtc::try_from("2025-07-12").unwrap();
    let _reward_period = RewardPeriod::new(from, to).expect("Failed to create reward period");

    let mut rewardables = RegistryQuerier::get_rewardable_nodes_per_provider::<DummyState>(
        &*REGISTRY_STORE.with(|store| store.clone()),
        from,
        to,
        None,
    )
    .expect("Failed to fetch rewardables");

    let np_1_id = PrincipalId::new_user_test_id(20);
    let np_1_rewardables = rewardables
        .remove(&np_1_id)
        .expect("No rewardables for node provider");

    let node_1_rewardable_days = node_rewardable_days(&np_1_rewardables, node_1_id);

    let expected_days: Vec<DayUtc> = vec![
        DayUtc::try_from("2025-07-07").unwrap(),
        // On 2025-07-08, node_1 was deleted, so it should not be rewardable until the 2025-07-11.
        DayUtc::try_from("2025-07-11").unwrap(),
        DayUtc::try_from("2025-07-12").unwrap(),
    ];

    assert_eq!(node_1_rewardable_days, expected_days);
}

#[test]
fn test_rewardables_nodes_provider_filtered() {
    let _client = client_for_tests();
    let from = DayUtc::try_from("2025-07-12").unwrap();
    let to = DayUtc::try_from("2025-07-17").unwrap();
    let _reward_period = RewardPeriod::new(from, to).expect("Failed to create reward period");
    let np_2_id = PrincipalId::new_user_test_id(50);

    let rewardables = RegistryQuerier::get_rewardable_nodes_per_provider::<DummyState>(
        &*REGISTRY_STORE.with(|store| store.clone()),
        from,
        to,
        Some(np_2_id),
    )
    .expect("Failed to fetch rewardable nodes");

    assert_eq!(rewardables.len(), 1);
    let np_2_rewardables = rewardables.get(&np_2_id).unwrap();
    assert_eq!(np_2_rewardables.len(), 1);
    let expected_node_4 = NodeId::from(PrincipalId::new_node_test_id(4));
    assert_eq!(np_2_rewardables[0].node_id, expected_node_4);
}

#[test]
fn test_node_operator_data_returns_expected_data() {
    let _client = client_for_tests();

    let version = 39667;
    let no_2_id = PrincipalId::new_user_test_id(30);
    let data = RegistryQuerier::node_operator_data(
        &*REGISTRY_STORE.with(|store| store.clone()),
        no_2_id,
        version.into(),
    )
    .unwrap()
    .unwrap();

    assert_eq!(data.node_provider_id, PrincipalId::new_user_test_id(20));
    assert_eq!(data.dc_id, "y");
    assert_eq!(data.region, "A");

    let version = 39675;
    let no_1_id = PrincipalId::new_user_test_id(10);
    let data = RegistryQuerier::node_operator_data(
        &*REGISTRY_STORE.with(|store| store.clone()),
        no_1_id,
        version.into(),
    )
    .unwrap()
    .unwrap();

    assert_eq!(data.node_provider_id, PrincipalId::new_user_test_id(20));
    assert_eq!(data.dc_id, "x");
    assert_eq!(data.region, "A");

    let not_yet_added_no_version = 39652;
    let data = RegistryQuerier::node_operator_data(
        &*REGISTRY_STORE.with(|store| store.clone()),
        no_1_id,
        not_yet_added_no_version.into(),
    )
    .unwrap();
    assert!(
        data.is_none(),
        "Data should not exist for version {not_yet_added_no_version} because Operator was not yet added"
    );
}
