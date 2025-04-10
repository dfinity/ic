use candid::{Decode, Encode};
use ic_base_types::PrincipalId;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, NODE_REWARDS_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_test_utils::common::{build_registry_wasm, NnsInitPayloadsBuilder};
use ic_nns_test_utils::state_test_helpers::{
    registry_latest_version, setup_nns_canisters_with_features,
    state_machine_builder_for_nns_tests, update, update_with_sender_bytes,
};
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
};
use ic_protobuf::registry::dc::v1::DataCenterRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::node_rewards::v2::{NodeRewardRate, NodeRewardRates, NodeRewardsTable};
use ic_registry_keys::{
    make_data_center_record_key, make_node_operator_record_key, NODE_REWARDS_TABLE_KEY,
};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_registry_transport::upsert;
use ic_state_machine_tests::StateMachine;
use maplit::btreemap;
use prost::Message;
use registry_canister::pb::v1::NodeProvidersMonthlyXdrRewards;
use std::collections::BTreeMap;
use std::str::FromStr;

#[test]
fn test_registry_and_node_rewards_give_same_results_with_normal_state() {
    let machine = state_machine_builder_for_nns_tests().build();

    let nr_table_1 = NodeRewardsTable {
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
    let nr_table_2 = NodeRewardsTable {
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
    let dc_1 = DataCenterRecord {
        id: "dc1".to_string(),
        region: "Africa,ZA".to_string(),
        owner: "David Bowie".to_string(),
        gps: None,
    };
    let dc_2 = DataCenterRecord {
        id: "dc2".to_string(),
        region: "Europe,CH".to_string(),
        owner: "Taylor Swift".to_string(),
        gps: None,
    };

    let node_operator_1_id = PrincipalId::new_user_test_id(42);
    let node_provider_1 = PrincipalId::from_str("djduj-3qcaa-aaaaa-aaaap-4ai").unwrap();
    let node_operator_1 = NodeOperatorRecord {
        node_operator_principal_id: node_operator_1_id.clone().to_vec(),
        node_allowance: 0,
        node_provider_principal_id: node_provider_1.to_vec(),
        dc_id: "dc1".to_string(),
        rewardable_nodes: btreemap! {
            "type3".to_string() => 3,
        },
        ipv6: None,
    };

    let node_operator_2_id = PrincipalId::new_user_test_id(44);
    let node_provider_2 = PrincipalId::from_str("ykqw2-6tyam-aaaaa-aaaap-4ai").unwrap();
    let node_operator_2 = NodeOperatorRecord {
        node_operator_principal_id: node_operator_2_id.clone().to_vec(),
        node_allowance: 0,
        node_provider_principal_id: node_provider_2.to_vec(),
        dc_id: "dc2".to_string(),
        rewardable_nodes: btreemap! {
            "type1".to_string() => 2,
        },
        ipv6: None,
    };

    // Loosely pulling inspiration from node_rewards/canister/src/test - add_registry_data_to_fake_registry
    let version_1 = vec![
        upsert(NODE_REWARDS_TABLE_KEY, nr_table_1.encode_to_vec()),
        upsert(make_data_center_record_key("dc1"), dc_1.encode_to_vec()),
    ];
    let version_2 = vec![upsert(
        make_node_operator_record_key(node_operator_1_id),
        node_operator_1.encode_to_vec(),
    )];
    let version_3 = vec![upsert(
        make_node_operator_record_key(node_operator_2_id),
        node_operator_2.encode_to_vec(),
    )];
    let version_4 = vec![upsert(
        make_data_center_record_key("dc2"),
        dc_2.encode_to_vec(),
    )];
    let version_5 = vec![upsert(NODE_REWARDS_TABLE_KEY, nr_table_2.encode_to_vec())];

    let mutate_requests = vec![version_1, version_2, version_3, version_4, version_5]
        .into_iter()
        .map(|mutations| RegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
        })
        .collect();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_initial_invariant_compliant_mutations()
        .with_initial_mutations(mutate_requests)
        .with_test_neurons()
        .build();

    setup_nns_canisters_with_features(&machine, nns_init_payload, &[]);

    do_test_registry_and_node_rewards_give_same_results(&machine);
}

fn get_rewards_at_version_with_registry(
    machine: &StateMachine,
    version: Option<u64>,
) -> Result<(BTreeMap<PrincipalId, u64>, Option<u64>), String> {
    update_with_sender_bytes(
        machine,
        REGISTRY_CANISTER_ID,
        "get_node_providers_monthly_xdr_rewards",
        Encode!(
            &ic_registry_canister_api::GetNodeProvidersMonthlyXdrRewardsRequest {
                registry_version: version,
            }
        )
        .unwrap(),
        GOVERNANCE_CANISTER_ID.get(),
    )
    .and_then(|r| {
        Decode!(
            &r,
            Result<NodeProvidersMonthlyXdrRewards, String>
        )
        .map_err(|e| format!("{}", e))
    })?
    .map(|response| {
        let NodeProvidersMonthlyXdrRewards {
            rewards,
            registry_version,
        } = response;

        let rewards = rewards
            .into_iter()
            .map(|(principal_str, amount)| {
                (
                    PrincipalId::from_str(&principal_str)
                        .expect("Could not get principal from string"),
                    amount,
                )
            })
            .collect();

        (rewards, registry_version)
    })
}

fn get_rewards_at_version_with_node_rewards_canister(
    machine: &StateMachine,
    version: Option<u64>,
) -> Result<(BTreeMap<PrincipalId, u64>, Option<u64>), String> {
    update(
        machine,
        NODE_REWARDS_CANISTER_ID,
        "get_node_providers_monthly_xdr_rewards",
        Encode!(&GetNodeProvidersMonthlyXdrRewardsRequest {
            registry_version: version,
        })
        .unwrap(),
    )
    .and_then(|r| {
        Decode!(&r, GetNodeProvidersMonthlyXdrRewardsResponse).map_err(|e| format!("{}", e))
    })
    .and_then(|response| {
        let GetNodeProvidersMonthlyXdrRewardsResponse { rewards, error } = response;

        if let Some(err_msg) = error {
            return Err(err_msg);
        }

        if let Some(rewards) = rewards {
            let ic_node_rewards_canister_api::monthly_rewards::NodeProvidersMonthlyXdrRewards {
                rewards,
                registry_version,
            } = rewards;
            let rewards = rewards
                .into_iter()
                .map(|(principal, amount)| (PrincipalId::from(principal), amount))
                .collect();
            return Ok((rewards, registry_version));
        }

        Err(
            "get_node_providers_monthly_xdr_rewards returned empty response, \
                which should be impossible."
                .to_string(),
        )
    })
}

// #[test]
// fn test_registry_and_node_rewards_give_same_results_with_golden_state() {
//     let machine = new_state_machine_with_golden_nns_state_or_panic();
//     do_test_registry_and_node_rewards_give_same_results(&machine);
// }

fn do_test_registry_and_node_rewards_give_same_results(machine: &StateMachine) {
    machine
        .upgrade_canister(REGISTRY_CANISTER_ID, build_registry_wasm().bytes(), vec![])
        .expect("Failed to upgrade registry");

    let latest_registry_version =
        registry_latest_version(machine).expect("Could not fetch latest version");

    println!("Latest Registry Version: {}", latest_registry_version);

    // Compare most recent 10, ensuring the errors are the same
    let latest_up_to_10 = (0..=latest_registry_version).rev().take(10);

    let compare = |version: Option<u64>| {
        let registry_result = get_rewards_at_version_with_registry(machine, version);
        let nr_result = get_rewards_at_version_with_node_rewards_canister(machine, version);

        if registry_result.is_err() {
            assert!(
                nr_result.is_err(),
                "Expected error at version: {version:?} because of registry response: {:?}",
                registry_result
            );
        }

        assert_eq!(registry_result, nr_result, "Version: {:?}", version);
    };

    for version in latest_up_to_10 {
        let version = Some(version);
        compare(version);
    }

    if latest_registry_version > 100 {
        // TODO DO NOT MERGE
        // Next steps - create a jittery random number generator that
        // samples the registry version and then calls both canisters
        // and compares the results.

        // ALSO TODO: ?? I forgot.... hope it wasn't important
    }
}
