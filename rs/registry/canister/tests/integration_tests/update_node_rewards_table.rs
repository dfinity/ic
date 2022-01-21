use assert_matches::assert_matches;
use candid::Encode;
use dfn_candid::candid_one;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value, invariant_compliant_mutation_as_atomic_req},
};
use ic_protobuf::registry::node_rewards::v2::{
    NodeRewardRate, NodeRewardRates, NodeRewardsTable, UpdateNodeRewardsTableProposalPayload,
};
use ic_registry_keys::NODE_REWARDS_TABLE_KEY;
use maplit::btreemap;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use std::collections::BTreeMap;

#[test]
fn test_the_anonymous_user_cannot_update_the_node_rewards_table() {
    local_test_on_nns_subnet(|runtime| async move {
        let initial_node_table = NodeRewardsTable {
            table: BTreeMap::new(),
        };

        let mut registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .build(),
        )
        .await;

        let new_entries = btreemap! {
            "CH".to_string() =>  NodeRewardRates {
                rates: btreemap!{
                    "default".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 240,
                    },
                    "small".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 350,
                    },
                }
            }
        };

        let payload = UpdateNodeRewardsTableProposalPayload { new_entries };

        // The anonymous end-user tries to update the node rewards table, bypassing
        // the proposals canister. This should be rejected.
        let response: Result<(), String> = registry
            .update_("update_node_rewards_table", candid_one, payload.clone())
            .await;

        assert_matches!(
            response,
            Err(s) if s.contains("is not authorized to call this method: update_node_rewards_table")
        );

        // .. And no change should have happened to the node rewards table
        let table =
            get_value::<NodeRewardsTable>(&registry, NODE_REWARDS_TABLE_KEY.as_bytes()).await;
        assert_eq!(table, initial_node_table);

        // Go through an upgrade cycle, and verify that it still works the same
        registry.upgrade_to_self_binary(vec![]).await.unwrap();
        let response: Result<(), String> = registry
            .update_("update_node_rewards_table", candid_one, payload.clone())
            .await;

        assert_matches!(
            response,
            Err(s) if s.contains("is not authorized to call this method: update_node_rewards_table")
        );

        let table =
            get_value::<NodeRewardsTable>(&registry, NODE_REWARDS_TABLE_KEY.as_bytes()).await;
        assert_eq!(table, initial_node_table);

        Ok(())
    });
}

#[test]
fn test_a_canister_other_than_the_governance_canister_cannot_update_the_node_rewards_table() {
    local_test_on_nns_subnet(|runtime| async move {
        let initial_node_table = NodeRewardsTable {
            table: BTreeMap::new(),
        };

        // An attacker got a canister that is trying to pass for the Governance
        // canister...
        let attacker_canister = set_up_universal_canister(&runtime).await;
        // ... but thankfully, it does not have the right ID
        assert_ne!(
            attacker_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .build(),
        )
        .await;

        let new_entries = btreemap! {
            "CH".to_string() =>  NodeRewardRates {
                rates: btreemap!{
                    "default".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 240,
                    },
                    "small".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 350,
                    },
                }
            }
        };

        let payload = UpdateNodeRewardsTableProposalPayload { new_entries };

        // The attacker canister tries to update the node rewards table, pretending
        // to be the Governance canister. This should have no effect.
        assert!(
            !forward_call_via_universal_canister(
                &attacker_canister,
                &registry,
                "update_node_rewards_table",
                Encode!(&payload).unwrap(),
            )
            .await
        );

        let table =
            get_value::<NodeRewardsTable>(&registry, NODE_REWARDS_TABLE_KEY.as_bytes()).await;
        assert_eq!(table, initial_node_table);

        Ok(())
    });
}

#[test]
fn test_the_governance_canister_can_update_the_node_rewards_table() {
    local_test_on_nns_subnet(|runtime| async move {
        let registry = set_up_registry_canister(
            &runtime,
            RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .build(),
        )
        .await;

        // Install the universal canister in place of the Governance canister
        let fake_governance_canister = set_up_universal_canister(&runtime).await;
        // Since it takes the id reserved for the governance canister, it can
        // impersonate it
        assert_eq!(
            fake_governance_canister.canister_id(),
            ic_nns_constants::GOVERNANCE_CANISTER_ID
        );

        let new_entries = btreemap! {
            "CH".to_string() =>  NodeRewardRates {
                rates: btreemap!{
                    "default".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 240,
                    },
                    "small".to_string() => NodeRewardRate {
                        xdr_permyriad_per_node_per_month: 350,
                    },
                }
            }
        };

        let payload = UpdateNodeRewardsTableProposalPayload { new_entries };

        assert!(
            forward_call_via_universal_canister(
                &fake_governance_canister,
                &registry,
                "update_node_rewards_table",
                Encode!(&payload).unwrap(),
            )
            .await
        );

        let table =
            get_value::<NodeRewardsTable>(&registry, NODE_REWARDS_TABLE_KEY.as_bytes()).await;

        assert_eq!(table.table.len(), 1);

        let ch = &table.table.get("CH").unwrap().rates;
        assert_eq!(
            ch.get("default").unwrap().xdr_permyriad_per_node_per_month,
            240
        );
        assert_eq!(
            ch.get("small").unwrap().xdr_permyriad_per_node_per_month,
            350
        );
        assert!(ch.get("storage_upgrade").is_none());

        Ok(())
    });
}
