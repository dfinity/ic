use crate::canister::NodeRewardsCanister;
use futures_util::FutureExt;
use ic_nervous_system_canisters::registry::FakeRegistry;
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
    NodeProvidersMonthlyXdrRewards,
};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates, NodeRewardsTable};
use ic_registry_canister_client::{
    test_registry_data_stable_memory_impl, StableCanisterRegistryClient,
};
use ic_registry_canister_client::{
    RegistryDataStableMemory, StorableRegistryKey, StorableRegistryValue,
};
use ic_registry_keys::{
    make_data_center_record_key, make_node_operator_record_key, NODE_REWARDS_TABLE_KEY,
};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use ic_types::PrincipalId;
use maplit::btreemap;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

pub type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static STATE: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>> = RefCell::new({
        let mgr = MemoryManager::init(DefaultMemoryImpl::default());
        StableBTreeMap::init(mgr.get(MemoryId::new(0)))
    });
}

test_registry_data_stable_memory_impl!(TestState, STATE);

fn setup_canister_for_test() -> (NodeRewardsCanister, Arc<FakeRegistry>) {
    let fake_registry = Arc::new(FakeRegistry::new());
    let registry_client = Arc::new(StableCanisterRegistryClient::<TestState>::new(
        fake_registry.clone(),
    ));
    let canister = NodeRewardsCanister::new(registry_client.clone());
    // In the actual canister,  there are 3 things to keep track of for tests
    // I ahve the store, the registry client, and the actual canister
    // I have memory, but that's abstracted away by the interface
    (canister, fake_registry)
}

fn add_registry_data_to_fake_registry(fake_registry: Arc<FakeRegistry>) {
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
    let (test_canister, fake_registry) = setup_canister_for_test();
    add_registry_data_to_fake_registry(fake_registry);

    thread_local! {
        // Dummy value b/c we can't do direct assignment using values defined above.
        static CANISTER: RefCell<NodeRewardsCanister> = RefCell::new(NodeRewardsCanister::new(
                Arc::new(StableCanisterRegistryClient::<TestState>::new(Arc::new(FakeRegistry::default()))),
        ));
    }
    CANISTER.with_borrow_mut(|canister| *canister = test_canister);

    let test_at_version =
        |registry_version: Option<u64>, expected: Result<BTreeMap<&str, u64>, String>| {
            let request = GetNodeProvidersMonthlyXdrRewardsRequest { registry_version };
            let result =
                NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(&CANISTER, request)
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
