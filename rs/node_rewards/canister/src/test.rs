use crate::canister::NodeRewardsCanister;
use crate::storage::RegistryStoreStableMemoryBorrower;
use ic_nervous_system_canisters::registry::{FakeRegistry, RegistryCanister};
use ic_node_rewards_canister_api::monthly_rewards::GetNodeProvidersMonthlyXdrRewardsRequest;
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates, NodeRewardsTable};
use ic_registry_canister_client::{registry_data_stable_memory_impl, StableCanisterRegistryClient};
use ic_registry_canister_client::{
    CanisterRegistryClient, RegistryDataStableMemory, StorableRegistryKey, StorableRegistryValue,
};
use ic_registry_node_provider_rewards::logs::RewardsPerNodeProviderLog;
use ic_registry_node_provider_rewards::RewardsPerNodeProvider;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap};
use ic_types::PrincipalId;
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
    let fake_registry = Arc::new(FakeRegistry::new(Default::default(), Default::default()));
    let registry_client = Arc::new(StableCanisterRegistryClient::<TestState>::new(
        fake_registry.clone(),
    ));
    let canister = NodeRewardsCanister::new(registry_client.clone());
    // In the actual canister,  there are 3 things to keep track of for tests
    // I ahve the store, the registry client, and the actual canister
    // I have memory, but that's abstracted away by the interface
    (canister, registry_client, fake_registry)
}

#[test]
fn test_rewards_calculation() {
    let (canister, client, fake_registry) = setup_canister_for_test();
    thread_local! {
        static CANISTER: RefCell<NodeRewardsCanister> = RefCell::new(canister);
    }

    let request = GetNodeProvidersMonthlyXdrRewardsRequest {};

    let result = NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
        &CANISTER,
        client.clone(),
        request,
    );

    // First populate our registry with enough data to run the rewards

    // Then, call the function that will run the rewards

    // Assert that the rewards are populated as expected.
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
