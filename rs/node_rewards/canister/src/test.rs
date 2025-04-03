use crate::canister::NodeRewardsCanister;
use futures_util::FutureExt;
use ic_nervous_system_canisters::registry::{FakeRegistry, FakeRegistryResponses};
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
    NodeProvidersMonthlyXdrRewards,
};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates, NodeRewardsTable};
use ic_registry_canister_client::{registry_data_stable_memory_impl, StableCanisterRegistryClient};
use ic_registry_canister_client::{
    RegistryDataStableMemory, StorableRegistryKey, StorableRegistryValue,
};
use ic_registry_keys::{
    make_data_center_record_key, make_node_operator_record_key, NODE_REWARDS_TABLE_KEY,
};
use ic_registry_transport::pb::v1::{RegistryDelta, RegistryValue};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use ic_types::{PrincipalId, RegistryVersion};
use maplit::btreemap;
use std::cell::RefCell;
use std::str::FromStr;
use std::sync::Arc;

pub type VM = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static STATE: RefCell<StableBTreeMap<StorableRegistryKey, StorableRegistryValue, VM>> = RefCell::new({
        let mgr = MemoryManager::init(DefaultMemoryImpl::default());
        StableBTreeMap::init(mgr.get(MemoryId::new(0)))
    });
}

registry_data_stable_memory_impl!(TestState, STATE);

fn setup_canister_for_test() -> (
    NodeRewardsCanister,
    Arc<StableCanisterRegistryClient<TestState>>,
    Arc<FakeRegistry>,
) {
    let fake_registry = Arc::new(FakeRegistry::new());
    let registry_client = Arc::new(StableCanisterRegistryClient::<TestState>::new(
        fake_registry.clone(),
    ));
    let canister = NodeRewardsCanister::new(registry_client.clone());
    // In the actual canister,  there are 3 things to keep track of for tests
    // I ahve the store, the registry client, and the actual canister
    // I have memory, but that's abstracted away by the interface
    (canister, registry_client, fake_registry)
}

fn reg_value<T>(version: u64, value: Option<T>) -> RegistryValue
where
    T: prost::Message + Default,
{
    let deletion_marker = value.is_none();
    let value = value
        .map(|v| {
            let mut buf = Vec::new();
            v.encode(&mut buf).expect("Failed to encode value");
            buf
        })
        .unwrap_or_default();

    RegistryValue {
        value,
        version,
        deletion_marker,
    }
}

fn reg_delta(key: impl AsRef<[u8]>, values: Vec<RegistryValue>) -> RegistryDelta {
    RegistryDelta {
        key: key.as_ref().to_vec(),
        values,
    }
}

fn add_registry_data_to_fake_registry(fake_registry: Arc<FakeRegistry>) {
    let previous_rewards_table = NodeRewardsTable {
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
    fake_registry.encode_value_at_version(NODE_REWARDS_TABLE_KEY, 4, Some(previous_rewards_table));

    let latest_rewards_table = NodeRewardsTable {
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

    fake_registry.encode_value_at_version(NODE_REWARDS_TABLE_KEY, 5, Some(latest_rewards_table));

    // Node Operators
    let node_operator_a_id = PrincipalId::from_str("djduj-3qcaa-aaaaa-aaaap-4ai").unwrap();
    let node_operator_b_id = PrincipalId::from_str("ykqw2-6tyam-aaaaa-aaaap-4ai").unwrap();

    fake_registry.encode_value_at_version(
        make_node_operator_record_key(node_operator_a_id),
        4,
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
        4,
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
        4,
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
    let (test_canister, client, fake_registry) = setup_canister_for_test();
    add_registry_data_to_fake_registry(fake_registry);

    thread_local! {
        // Dummy value b/c we can't do direct assignment using values defined above.
        static CANISTER: RefCell<NodeRewardsCanister> = RefCell::new(NodeRewardsCanister::new(
                Arc::new(StableCanisterRegistryClient::<TestState>::new(Arc::new(FakeRegistry::default()))),
        ));
    }
    CANISTER.with_borrow_mut(|canister| *canister = test_canister);

    let request = GetNodeProvidersMonthlyXdrRewardsRequest {
        registry_version: None,
    };

    let result = NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
        &CANISTER,
        client.clone(),
        request,
    )
    .now_or_never()
    .unwrap();

    let expected_latest_result = GetNodeProvidersMonthlyXdrRewardsResponse {
        rewards: Some(NodeProvidersMonthlyXdrRewards {
            rewards: btreemap! {
                PrincipalId::from_str("djduj-3qcaa-aaaaa-aaaap-4ai").unwrap().0 => 80835271,
                PrincipalId::from_str("ykqw2-6tyam-aaaaa-aaaap-4ai").unwrap().0 => 24691356,
            },
            registry_version: Some(latest_version),
        }),
        error: None,
    };

    assert_eq!(result, expected_latest_result);

    // Test with same version, but explicitly
    let request = GetNodeProvidersMonthlyXdrRewardsRequest {
        registry_version: Some(latest_version),
    };

    let result_for_explicit_version_5 =
        NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
            &CANISTER,
            client.clone(),
            request,
        )
        .now_or_never()
        .unwrap();
    // should be the same.
    assert_eq!(result_for_explicit_version_5, expected_latest_result);

    // Test with a specific version
    let request = GetNodeProvidersMonthlyXdrRewardsRequest {
        registry_version: Some(4),
    };

    let actual_result_for_version_4 = NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
        &CANISTER,
        client.clone(),
        request,
    )
    .now_or_never()
    .unwrap();

    let expected_result_for_version_4 = GetNodeProvidersMonthlyXdrRewardsResponse {
        rewards: Some(NodeProvidersMonthlyXdrRewards {
            rewards: btreemap! {
                PrincipalId::from_str("djduj-3qcaa-aaaaa-aaaap-4ai").unwrap().0 => 294,
                PrincipalId::from_str("ykqw2-6tyam-aaaaa-aaaap-4ai").unwrap().0 => 400,
            },
            registry_version: Some(latest_version),
        }),
        error: None,
    };

    assert_eq!(actual_result_for_version_4, expected_result_for_version_4);
}
