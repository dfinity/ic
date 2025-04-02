use crate::canister::NodeRewardsCanister;
use crate::storage::RegistryStoreStableMemoryBorrower;
use futures_util::FutureExt;
use ic_nervous_system_canisters::registry::{
    FakeRegistry, FakeRegistryResponses, RegistryCanister,
};
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
    NodeProvidersMonthlyXdrRewards,
};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates, NodeRewardsTable};
use ic_registry_canister_client::{registry_data_stable_memory_impl, StableCanisterRegistryClient};
use ic_registry_canister_client::{
    CanisterRegistryClient, RegistryDataStableMemory, StorableRegistryKey, StorableRegistryValue,
};
use ic_registry_keys::{
    make_api_boundary_node_record_key, make_data_center_record_key, make_node_operator_record_key,
    NODE_REWARDS_TABLE_KEY,
};
use ic_registry_node_provider_rewards::logs::RewardsPerNodeProviderLog;
use ic_registry_node_provider_rewards::RewardsPerNodeProvider;
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

fn setup_canister_for_test(
    fake_registry_version: u64,
    fake_registry_responses: FakeRegistryResponses,
) -> (
    NodeRewardsCanister,
    Arc<StableCanisterRegistryClient<TestState>>,
    Arc<FakeRegistry>,
) {
    let fake_registry = Arc::new(FakeRegistry::new(
        RegistryVersion::new(fake_registry_version),
        fake_registry_responses,
    ));
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

fn fake_registry_responses_for_rewards_calculation_test(
    version_of_records: u64,
) -> FakeRegistryResponses {
    // This is what we are creating, so that we can mock registry
    let mut deltas = vec![];

    let rewards_table = NodeRewardsTable {
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

    deltas.push(reg_delta(
        NODE_REWARDS_TABLE_KEY,
        vec![reg_value(version_of_records, Some(rewards_table))],
    ));

    // Node Operators
    let node_operator_a_id = PrincipalId::from_str("djduj-3qcaa-aaaaa-aaaap-4ai").unwrap();
    let node_operator_b_id = PrincipalId::from_str("ykqw2-6tyam-aaaaa-aaaap-4ai").unwrap();

    deltas.push(reg_delta(
        make_node_operator_record_key(node_operator_a_id),
        vec![reg_value(
            version_of_records,
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
        )],
    ));

    deltas.push(reg_delta(
        make_node_operator_record_key(node_operator_b_id),
        vec![reg_value(
            version_of_records,
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
        )],
    ));

    // Data Centers

    deltas.push(reg_delta(
        make_data_center_record_key("dc1"),
        vec![reg_value(
            version_of_records,
            Some(DataCenterRecord {
                id: "dc1".to_string(),
                region: "Africa,ZA".to_string(),
                owner: "David Bowie".to_string(),
                gps: None,
            }),
        )],
    ));

    deltas.push(reg_delta(
        make_data_center_record_key("dc2"),
        vec![reg_value(
            version_of_records,
            Some(DataCenterRecord {
                id: "dc2".to_string(),
                region: "Europe,CH".to_string(),
                owner: "Taylor Swift".to_string(),
                gps: None,
            }),
        )],
    ));

    let mut fake_registry_responses = FakeRegistryResponses::new();
    fake_registry_responses.insert(0, Ok(deltas));

    fake_registry_responses
}

#[test]
fn test_rewards_calculation() {
    let latest_version = 5;
    let fake_registry_responses =
        fake_registry_responses_for_rewards_calculation_test(latest_version);

    let (test_canister, client, _fake_registry) =
        setup_canister_for_test(latest_version, fake_registry_responses);

    thread_local! {
        // Dummy value b/c we can't do direct assignment
        static CANISTER: RefCell<NodeRewardsCanister> = RefCell::new(NodeRewardsCanister::new(
                Arc::new(StableCanisterRegistryClient::<TestState>::new(Arc::new(FakeRegistry::default()))),
        ));
    }
    CANISTER.with_borrow_mut(|canister| *canister = test_canister);

    let request = GetNodeProvidersMonthlyXdrRewardsRequest {};

    let result = NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(
        &CANISTER,
        client.clone(),
        request,
    )
    .now_or_never()
    .unwrap();

    let expected_result = GetNodeProvidersMonthlyXdrRewardsResponse {
        rewards: Some(NodeProvidersMonthlyXdrRewards {
            rewards: btreemap! {
                PrincipalId::from_str("djduj-3qcaa-aaaaa-aaaap-4ai").unwrap().0 => 80835271,
                PrincipalId::from_str("ykqw2-6tyam-aaaaa-aaaap-4ai").unwrap().0 => 24691356,
            },
            registry_version: Some(latest_version),
        }),
        error: None,
    };

    assert_eq!(result, expected_result);
}
// /// Test type1 nodes because they are being deprecated, setting the corresponding rewards
// /// to zero is part of that process.
// /// Test type3 nodes because they involve more a complex calculation that all other types.
// fn run_rewards_table_with_type1_rewards_test(type1_xdr_permyriad_per_node_per_month: u64) {
//     let type3_xdr_permyriad_per_node_per_month = 27491250;
//
//     let rewards_table = NodeRewardsTable {
//         table: btreemap! {
//             "Africa,ZA".to_string() => NodeRewardRates {
//                 rates: btreemap! {
//                     "type3".to_string() => NodeRewardRate {
//                         xdr_permyriad_per_node_per_month: type3_xdr_permyriad_per_node_per_month,
//                         reward_coefficient_percent: Some(98),
//                     }
//                 }
//             },
//             "Europe,CH".to_string() => NodeRewardRates {
//                 rates: btreemap! {
//                     "type1".to_string() => NodeRewardRate {
//                         xdr_permyriad_per_node_per_month: type1_xdr_permyriad_per_node_per_month,
//                         reward_coefficient_percent: None,
//                     }
//                 }
//             }
//         },
//     };
//
//     let node_operator_a_id = PrincipalId::from_str("djduj-3qcaa-aaaaa-aaaap-4ai").unwrap();
//     let node_operator_b_id = PrincipalId::from_str("ykqw2-6tyam-aaaaa-aaaap-4ai").unwrap();
//
//     let node_operators = [
//         (
//             "node_operator_a".to_string(),
//             NodeOperatorRecord {
//                 node_operator_principal_id: PrincipalId::new_user_test_id(42).to_vec(),
//                 node_allowance: 0,
//                 node_provider_principal_id: node_operator_a_id.to_vec(),
//                 dc_id: "dc1".to_string(),
//                 rewardable_nodes: btreemap! {
//                     "type3".to_string() => 3,
//                 },
//                 ipv6: None,
//             },
//         ),
//         (
//             "node_operator_b".to_string(),
//             NodeOperatorRecord {
//                 node_operator_principal_id: PrincipalId::new_user_test_id(44).to_vec(),
//                 node_allowance: 0,
//                 node_provider_principal_id: node_operator_b_id.to_vec(),
//                 dc_id: "dc2".to_string(),
//                 rewardable_nodes: btreemap! {
//                     "type1".to_string() => 2,
//                 },
//                 ipv6: None,
//             },
//         ),
//     ];
//
//     let data_centers = btreemap! {
//         "dc1".to_string() => DataCenterRecord {
//             id: "dc1".to_string(),
//             region: "Africa,ZA".to_string(),
//             owner: "David Bowie".to_string(),
//             gps: None,
//         },
//         "dc2".to_string() => DataCenterRecord {
//             id: "dc2".to_string(),
//             region: "Europe,CH".to_string(),
//             owner: "Taylor Swift".to_string(),
//             gps: None,
//         },
//     };
//
//     let expected_node_operator_a_rewards = 80835271;
//     // Smoke test - type3 adds fewer rewards to subsequent nodes.
//     assert!(expected_node_operator_a_rewards < 3 * type3_xdr_permyriad_per_node_per_month);
//
//     let expected_node_operator_b_rewards = 2 * type1_xdr_permyriad_per_node_per_month;
//
//     assert_eq!(
//         result,
//         Ok(RewardsPerNodeProvider {
//             rewards_per_node_provider: btreemap! {
//                 node_operator_a_id => expected_node_operator_a_rewards,
//                 node_operator_b_id => expected_node_operator_b_rewards,
//             },
//             computation_log: btreemap! {
//                 node_operator_a_id => RewardsPerNodeProviderLog {
//                     node_provider_id: node_operator_a_id,
//                     entries: vec![
//                         LogEntry::NodeRewards {
//                             node_type: "type3".to_string(),
//                             node_idx: 0,
//                             dc_id: "dc1".to_string(),
//                             rewardable_count: 3,
//                             rewards_xdr_permyriad: 27491250,
//                         },
//                         LogEntry::NodeRewards {
//                             node_type: "type3".to_string(),
//                             node_idx: 1,
//                             dc_id: "dc1".to_string(),
//                             rewardable_count: 3,
//                             rewards_xdr_permyriad: 26941425,
//                         },
//                         LogEntry::NodeRewards {
//                             node_type: "type3".to_string(),
//                             node_idx: 2,
//                             dc_id: "dc1".to_string(),
//                             rewardable_count: 3,
//                             rewards_xdr_permyriad: 26402596,
//                         },
//                         LogEntry::DCRewards {
//                             dc_id: "dc1".to_string(),
//                             node_type: "type3".to_string(),
//                             rewardable_count: 3,
//                             rewards_xdr_permyriad: expected_node_operator_a_rewards,
//                         },
//                     ]
//                 },
//                 node_operator_b_id => RewardsPerNodeProviderLog {
//                     node_provider_id: node_operator_b_id,
//                     entries: vec![
//                         LogEntry::DCRewards {
//                             dc_id: "dc2".to_string(),
//                             node_type: "type1".to_string(),
//                             rewardable_count: 2,
//                             rewards_xdr_permyriad: expected_node_operator_b_rewards,
//                         },
//                     ]
//                 },
//             }
//         })
//     );
// }
