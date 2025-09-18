use crate::canister::NodeRewardsCanister;
use crate::canister::test::test_utils::{CANISTER_TEST, setup_thread_local_canister_for_test};
use futures_util::FutureExt;
use ic_nervous_system_canisters::registry::fake::FakeRegistry;
use ic_nns_test_utils::registry::invariant_compliant_mutation;
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
    NodeProvidersMonthlyXdrRewards,
};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::{
    NodeRewardRate, NodeRewardRates, NodeRewardsTable, UpdateNodeRewardsTableProposalPayload,
};
use ic_registry_keys::{
    NODE_REWARDS_TABLE_KEY, make_data_center_record_key, make_node_operator_record_key,
};
use ic_types::PrincipalId;
use maplit::btreemap;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

fn setup_data_for_test_rewards_calculation(fake_registry: Arc<FakeRegistry>) {
    let version_1_rewards_table = NodeRewardsTable {
        table: btreemap! {
            "Africa,ZA".to_string() => NodeRewardRates {
                rates: btreemap! {
                    "type3".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 100,
                        reward_coefficient_percent: Some(98),
                    }
                }
            },
            "Europe,CH".to_string() => NodeRewardRates {
                rates: btreemap! {
                    "type1".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 200,
                        reward_coefficient_percent: None,
                    }
                }
            }
        },
    };
    fake_registry.encode_value_at_version(NODE_REWARDS_TABLE_KEY, 1, Some(version_1_rewards_table));

    let version_5_rewards_table = NodeRewardsTable {
        table: btreemap! {
            "Africa,ZA".to_string() => NodeRewardRates {
                rates: btreemap! {
                    "type3".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 27491250,
                        reward_coefficient_percent: Some(98),
                    }
                }
            },
            "Europe,CH".to_string() => NodeRewardRates {
                rates: btreemap! {
                    "type1".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 12345678,
                        reward_coefficient_percent: None,
                    }
                }
            }
        },
    };

    fake_registry.encode_value_at_version(NODE_REWARDS_TABLE_KEY, 5, Some(version_5_rewards_table));

    // Node Operators
    let node_operator_a_id = PrincipalId::from_str("djduj-3qcaa-aaaaa-aaaap-4ai").unwrap();
    let node_operator_b_id = PrincipalId::from_str("ykqw2-6tyam-aaaaa-aaaap-4ai").unwrap();

    fake_registry.encode_value_at_version(
        make_node_operator_record_key(node_operator_a_id),
        2,
        Some(NodeOperatorRecord {
            node_operator_principal_id: PrincipalId::new_user_test_id(42).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: node_operator_a_id.to_vec(),
            dc_id: "dc1".to_string(),
            rewardable_nodes: btreemap! {
                "type3".to_string() => 3,
            },
            ipv6: None,
            max_rewardable_nodes: Default::default(),
        }),
    );

    fake_registry.encode_value_at_version(
        make_node_operator_record_key(node_operator_b_id),
        3,
        Some(NodeOperatorRecord {
            node_operator_principal_id: PrincipalId::new_user_test_id(44).to_vec(),
            node_allowance: 0,
            node_provider_principal_id: node_operator_b_id.to_vec(),
            dc_id: "dc2".to_string(),
            rewardable_nodes: btreemap! {
                "type1".to_string() => 2,
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
            region: "Africa,ZA".to_string(),
            owner: "David Bowie".to_string(),
            gps: None,
        }),
    );

    fake_registry.encode_value_at_version(
        make_data_center_record_key("dc2"),
        4,
        Some(DataCenterRecord {
            id: "dc2".to_string(),
            region: "Europe,CH".to_string(),
            owner: "Taylor Swift".to_string(),
            gps: None,
        }),
    );
}

#[test]
fn test_rewards_calculation() {
    let latest_version = 5;
    let (fake_registry, _) = setup_thread_local_canister_for_test();
    setup_data_for_test_rewards_calculation(fake_registry);

    let test_at_version =
        |registry_version: Option<u64>, expected: Result<BTreeMap<&str, u64>, String>| {
            let request = GetNodeProvidersMonthlyXdrRewardsRequest { registry_version };
            let result = NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
                &CANISTER_TEST,
                request,
            )
            .now_or_never()
            .unwrap();

            let expected_result = match expected {
                Ok(rewards) => {
                    let rewards = rewards
                        .into_iter()
                        .map(|(k, v)| (PrincipalId::from_str(k).unwrap().0, v))
                        .collect();
                    GetNodeProvidersMonthlyXdrRewardsResponse {
                        rewards: Some(NodeProvidersMonthlyXdrRewards {
                            rewards,
                            registry_version: registry_version.or(Some(latest_version)),
                        }),
                        error: None,
                    }
                }
                Err(msg) => GetNodeProvidersMonthlyXdrRewardsResponse {
                    rewards: None,
                    error: Some(msg),
                },
            };

            assert_eq!(result, expected_result);
        };

    // We test with the different versions to make sure that the rewards are sensitive to
    // changing versions for each component.

    // Version 1
    test_at_version(Some(1), Ok(btreemap! {}));
    // Version 2
    test_at_version(
        Some(2),
        Ok(btreemap! {"djduj-3qcaa-aaaaa-aaaap-4ai" => 294}),
    );
    // Version 3
    test_at_version(
        Some(3),
        Err("Node Operator with key 'jpjxp-djmaa-aaaaa-aaaap-4ai' \
             has data center ID 'dc2' not found in the Registry"
            .to_string()),
    );
    // Version 4
    test_at_version(
        Some(4),
        Ok(btreemap! {"djduj-3qcaa-aaaaa-aaaap-4ai" => 294, "ykqw2-6tyam-aaaaa-aaaap-4ai" => 400 }),
    );
    // Version 5
    test_at_version(
        Some(5),
        Ok(
            btreemap! {"djduj-3qcaa-aaaaa-aaaap-4ai" => 80835271, "ykqw2-6tyam-aaaaa-aaaap-4ai" => 24691356 },
        ),
    );
    // Latest
    test_at_version(
        None,
        Ok(
            btreemap! {"djduj-3qcaa-aaaaa-aaaap-4ai" => 80835271, "ykqw2-6tyam-aaaaa-aaaap-4ai" => 24691356 },
        ),
    );
}

// Tests ported from Registry (in registry/canister/src/get_node_providers_monthly_xdr_rewards.rs)
// These tests are for the first version of the voting rewards algorithm, and may need to be adjusted
// to take the "algorithm_version" parameter when it's introduced.

fn init_empty_registry(registry: Arc<FakeRegistry>) {
    let initial_mutations = invariant_compliant_mutation(0);
    assert_eq!(
        registry.latest_version(),
        0,
        "FakeRegistry should be uninitialized when calling this method"
    );
    registry.apply_mutations(initial_mutations);
}

fn add_node_operator_with_dc(
    registry: Arc<FakeRegistry>,
    np_principal: PrincipalId,
    no_principal: PrincipalId,
    dc_id: String,
    dc_region: String,
    node_allowance: u64,
    rewardable_nodes: BTreeMap<String, u32>,
) {
    let dc_id = dc_id.to_lowercase();
    let no_record = NodeOperatorRecord {
        node_operator_principal_id: no_principal.to_vec(),
        node_allowance,
        node_provider_principal_id: np_principal.to_vec(),
        dc_id: dc_id.clone(),
        rewardable_nodes: rewardable_nodes.clone(),
        ipv6: None,
        max_rewardable_nodes: Default::default(),
    };

    registry.encode_value(make_node_operator_record_key(no_principal), Some(no_record));
    let dc_owner = np_principal.to_string().split_at(5).0.to_string();
    add_data_center(registry, dc_id, dc_owner, dc_region);
}

fn add_data_center(registry: Arc<FakeRegistry>, dc_id: String, owner: String, region: String) {
    let data_center_record = DataCenterRecord {
        id: dc_id.clone(),
        region,
        owner,
        gps: None,
    };
    registry.encode_value(
        make_data_center_record_key(&dc_id),
        Some(data_center_record),
    );
}

fn update_node_rewards_table(
    registry: Arc<FakeRegistry>,
    entries: BTreeMap<String, NodeRewardRates>,
) {
    let mut current: NodeRewardsTable = registry
        .get_decoded_value(NODE_REWARDS_TABLE_KEY)
        .unwrap_or_default();
    current.extend(NodeRewardsTable { table: entries });
    registry.encode_value(NODE_REWARDS_TABLE_KEY, Some(current));
}

#[test]
fn test_get_node_providers_monthly_xdr_rewards_ignores_deleted_keys() {
    let (registry, _) = setup_thread_local_canister_for_test();
    init_empty_registry(registry.clone());

    let node_operator = PrincipalId::new_user_test_id(1);
    registry.encode_value(NODE_REWARDS_TABLE_KEY, Some(NodeRewardsTable::default()));
    registry.encode_value(
        make_node_operator_record_key(node_operator),
        Some(NodeOperatorRecord {
            node_operator_principal_id: node_operator.to_vec(),
            node_allowance: 1,
            node_provider_principal_id: PrincipalId::new_user_test_id(2).to_vec(),
            dc_id: "dc1".to_string(),
            rewardable_nodes: Default::default(),
            ipv6: None,
            max_rewardable_nodes: Default::default(),
        }),
    );

    // Simulate deletion
    registry.encode_value::<NodeRewardsTable>(make_node_operator_record_key(node_operator), None);

    assert_eq!(
        NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
            &CANISTER_TEST,
            GetNodeProvidersMonthlyXdrRewardsRequest {
                registry_version: None
            }
        )
        .now_or_never()
        .unwrap()
        .rewards,
        Some(NodeProvidersMonthlyXdrRewards {
            rewards: btreemap! {},
            registry_version: Some(registry.latest_version()),
        })
    );
}

#[test]
fn test_get_node_providers_monthly_xdr_rewards_gen1() {
    let (registry, _) = setup_thread_local_canister_for_test();
    init_empty_registry(registry.clone());

    let np1 = PrincipalId::new_user_test_id(1);
    add_node_operator_with_dc(
        registry.clone(),
        np1,
        np1,
        "NY1".to_string(),
        "North America,US,NY".into(),
        5,
        btreemap! { "type0".to_string() => 4, "type2".to_string() => 1 },
    );

    let np2 = PrincipalId::new_user_test_id(2);
    add_node_operator_with_dc(
        registry.clone(),
        np2,
        np2,
        "ZH3".to_string(),
        "Europe,CH,Zurich".into(),
        18,
        btreemap! { "type0".to_string() => 11, "type2".to_string() => 7 },
    );

    // Add regions to rewards table (but an empty map to test failure cases)
    let new_entries = btreemap! {
        "North America,US".to_string() =>  NodeRewardRates {
            rates: btreemap!{}
        },
    };

    update_node_rewards_table(registry.clone(), new_entries);

    ///////////////////////////////
    // Assert get_node_providers_monthly_xdr_rewards still provides default values
    ///////////////////////////////
    let response = NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
        &CANISTER_TEST,
        GetNodeProvidersMonthlyXdrRewardsRequest {
            registry_version: None,
        },
    )
    .now_or_never()
    .unwrap();

    let monthly_rewards = response.rewards.unwrap();
    let np1_rewards = monthly_rewards.rewards.get(&np1.0).unwrap();
    assert_eq!(*np1_rewards, 5); // 5 nodes at 1 XDR/month/node
    assert_eq!(
        monthly_rewards.registry_version,
        Some(registry.latest_version())
    );

    // Store this version to test specific version requests later.
    let version_without_rewards_table = registry.latest_version();

    ///////////////////////////////
    // Now add the reward table for type0 and type2 nodes and check that the values are properly used
    ///////////////////////////////
    let json = r#"{
            "North America,US,NY":         { "type0": [240, null]                                                          },
            "North America,US":            { "type0": [677, null],  "type2": [456, null]                                   },
            "North America":               { "type0": [801, null]                                                          },
            "Europe":                      { "type0": [68, null],   "type2": [11, null]                                    }
        }"#;

    let map: BTreeMap<String, BTreeMap<String, NodeRewardRate>> =
        serde_json::from_str(json).unwrap();
    let node_rewards_payload = UpdateNodeRewardsTableProposalPayload::from(map);
    update_node_rewards_table(registry.clone(), node_rewards_payload.new_entries);

    let response = NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
        &CANISTER_TEST,
        GetNodeProvidersMonthlyXdrRewardsRequest {
            registry_version: None,
        },
    )
    .now_or_never()
    .unwrap();

    let monthly_rewards = response.rewards.unwrap();

    // NP1: 4 'type0' nodes in 'North America,US,NY' + 1 'type2' node in 'North America,US'
    assert_eq!(
        *monthly_rewards.rewards.get(&np1.0).unwrap(),
        (4 * 240) + 456
    );
    // NP2: 11 'type0' nodes in 'Europe,CH,Zurich' + 7 'type2' nodes in 'CH'
    assert_eq!(
        *monthly_rewards.rewards.get(&np2.0).unwrap(),
        (11 * 68) + (7 * 11)
    );

    ///////////////////////////////
    // Now add the reward table entries for type3 rewards and confirm nothing changes for type0 and type2 nodes
    ///////////////////////////////
    let json = r#"{
            "North America,US,NY":         { "type3": [111, null] },
            "North America,US":            { "type3": [222, null] },
            "North America":               { "type3": [333, null] },
            "Europe":                      { "type3": [444, null] },
            "Asia":                        { "type3": [555, null] }
        }"#;

    let map: BTreeMap<String, BTreeMap<String, NodeRewardRate>> =
        serde_json::from_str(json).unwrap();
    let node_rewards_payload = UpdateNodeRewardsTableProposalPayload::from(map);
    update_node_rewards_table(registry.clone(), node_rewards_payload.new_entries);

    let response = NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
        &CANISTER_TEST,
        GetNodeProvidersMonthlyXdrRewardsRequest {
            registry_version: None,
        },
    )
    .now_or_never()
    .unwrap();

    let monthly_rewards = response.rewards.unwrap();

    // NP1: 4 'type0' nodes in 'North America,US,NY' + 1 'type2' node in 'North America,US'
    assert_eq!(
        *monthly_rewards.rewards.get(&np1.0).unwrap(),
        (4 * 240) + 456
    );
    // NP2: 11 'type0' nodes in 'Europe,CH,Zurich' + 7 'type2' nodes in 'CH'
    assert_eq!(
        *monthly_rewards.rewards.get(&np2.0).unwrap(),
        (11 * 68) + (7 * 11)
    );

    ///////////////////////////////
    // Test getting a previous version's rewards works
    ///////////////////////////////
    let response = NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
        &CANISTER_TEST,
        GetNodeProvidersMonthlyXdrRewardsRequest {
            registry_version: Some(version_without_rewards_table),
        },
    )
    .now_or_never()
    .unwrap();

    let monthly_rewards = response.rewards.unwrap();

    let np1_rewards = monthly_rewards.rewards.get(&np1.0).unwrap();
    assert_eq!(*np1_rewards, 5); // 5 nodes at 1 XDR/month/node
    assert_eq!(
        monthly_rewards.registry_version,
        Some(version_without_rewards_table)
    );
}

#[test]
fn test_get_node_providers_monthly_xdr_rewards_type3() {
    let (registry, _) = setup_thread_local_canister_for_test();
    init_empty_registry(registry.clone());

    let np1 = PrincipalId::new_user_test_id(1);
    add_node_operator_with_dc(
        registry.clone(),
        np1,
        np1,
        "ZH3".to_string(),
        "Europe,CH,Zurich".into(),
        28,
        btreemap! { "type0".to_string() => 14, "type2".to_string() => 11 },
    );

    let np2 = PrincipalId::new_user_test_id(2);
    add_node_operator_with_dc(
        registry.clone(),
        np2,
        np2,
        "ZH4".to_string(),
        "Europe,CH,Zurich".into(),
        28,
        btreemap! { "type3".to_string() => 14 },
    );

    ///////////////////////////////
    // Now add the reward table for type0/2/3 nodes and check that the values are properly used
    ///////////////////////////////
    let json = r#"{
            "North America,US":            { "type0": [100000, null],  "type2": [200000, null],  "type3": [300000, 70] },
            "North America,CA":            { "type0": [400000, null],  "type2": [500000, null],  "type3": [600000, 70] },
            "North America,US,California": { "type0": [700000, null],                            "type3": [800000, 70] },
            "North America,US,Florida":    { "type0": [900000, null],                            "type3": [1000000, 70] },
            "North America,US,Georgia":    { "type0": [1100000, null],                           "type3": [1200000, null] },
            "Asia,SG":                     { "type0": [10000000, 100],  "type2": [11000000, 100],  "type3": [12000000, 70] },
            "Asia":                        { "type0": [13000000, 100],  "type2": [14000000, 100],  "type3": [15000000, 70] },
            "Europe":                      { "type0": [20000000, null], "type2": [21000000, null], "type3": [22000000, 70] }
        }"#;

    let map: BTreeMap<String, BTreeMap<String, NodeRewardRate>> =
        serde_json::from_str(json).unwrap();
    let node_rewards_payload = UpdateNodeRewardsTableProposalPayload::from(map);
    update_node_rewards_table(registry.clone(), node_rewards_payload.new_entries);

    let response = NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
        &CANISTER_TEST,
        GetNodeProvidersMonthlyXdrRewardsRequest {
            registry_version: None,
        },
    )
    .now_or_never()
    .unwrap();

    let monthly_rewards = response.rewards.unwrap();
    assert_eq!(
        monthly_rewards.registry_version,
        Some(registry.latest_version())
    );

    // NP1: the existence of type3 nodes should not impact the type0/type2 rewards
    assert_eq!(
        *monthly_rewards.rewards.get(&np1.0).unwrap(),
        14 * 20000000 + 11 * 21000000
    );
    // NP2: type3 rewards are getting lower with each node the NP has
    // https://wiki.internetcomputer.org/wiki/Node_Provider_Remuneration
    let mut np2_expected_reward_ch = 0;
    let mut node_reward_ch = 22000000.0;
    for _ in 0..14 {
        println!("node_reward CH {node_reward_ch}");
        np2_expected_reward_ch += node_reward_ch as u64;
        node_reward_ch *= 0.7;
    }
    assert_eq!(
        *monthly_rewards.rewards.get(&np2.0).unwrap(),
        np2_expected_reward_ch
    );

    ///////////////////////////////
    // Now NP2 adds a new type3 DC in a different country (Germany), the rewards for the NP are again counted from the start
    ///////////////////////////////
    let no3 = PrincipalId::new_user_test_id(3);
    add_node_operator_with_dc(
        registry.clone(),
        np2,
        no3,
        "FR2".to_string(),
        "Europe,DE,Frankfurt".into(),
        11,
        btreemap! { "type3".to_string() => 11 },
    );

    let mut np2_expected_reward_de = 0;
    let mut node_reward_de = 22000000.0;
    for _ in 0..11 {
        println!("node_reward DE {node_reward_de}");
        np2_expected_reward_de += node_reward_de as u64;
        node_reward_de *= 0.7;
    }

    let response = NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
        &CANISTER_TEST,
        GetNodeProvidersMonthlyXdrRewardsRequest {
            registry_version: None,
        },
    )
    .now_or_never()
    .unwrap();

    let monthly_rewards = response.rewards.unwrap();

    assert_eq!(
        *monthly_rewards.rewards.get(&np2.0).unwrap(),
        np2_expected_reward_ch + np2_expected_reward_de
    );

    ///////////////////////////////
    // Now NP2 adds a new type3 DC in the same country as before, the rewards for the NP continue decreasing per node, even across DCs
    ///////////////////////////////
    let no4 = PrincipalId::new_user_test_id(4);
    add_node_operator_with_dc(
        registry,
        np2,
        no4,
        "BA1".to_string(),
        "Europe,CH,Basel".into(),
        10,
        btreemap! { "type3".to_string() => 10 },
    );

    for _ in 0..10 {
        println!("node_reward CH {node_reward_ch}");
        np2_expected_reward_ch += node_reward_ch as u64;
        node_reward_ch *= 0.7;
    }

    let response = NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
        &CANISTER_TEST,
        GetNodeProvidersMonthlyXdrRewardsRequest {
            registry_version: None,
        },
    )
    .now_or_never()
    .unwrap();

    let monthly_rewards = response.rewards.unwrap();

    assert_eq!(
        *monthly_rewards.rewards.get(&np2.0).unwrap(),
        np2_expected_reward_ch + np2_expected_reward_de
    );
}
