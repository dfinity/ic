use itertools::Itertools;
use std::{collections::BTreeMap, convert::TryFrom};

use assert_matches::assert_matches;

use candid::Encode;
use canister_test::PrincipalId;
use dfn_candid::candid;
use ic_base_types::NodeId;
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value_or_panic, prepare_registry, prepare_registry_with_two_node_sets},
};
use ic_protobuf::registry::subnet::v1::{SubnetListRecord, SubnetRecord};
use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_change_subnet_membership::ChangeSubnetMembershipPayload,
};

#[test]
fn test_the_anonymous_user_cannot_change_subnet_membership() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            let num_nodes_in_subnet = 4_usize;
            let (init_mutate, subnet_id, unassigned_node_ids, _) =
                prepare_registry(num_nodes_in_subnet, 3);
            let mut registry = set_up_registry_canister(
                &runtime,
                RegistryCanisterInitPayloadBuilder::new()
                    .push_init_mutate_request(init_mutate)
                    .build(),
            )
            .await;

            let node_ids_to_remove: Vec<NodeId> = get_value_or_panic::<SubnetRecord>(
                &registry,
                make_subnet_record_key(subnet_id).as_bytes(),
            )
            .await
            .membership
            .iter()
            .skip(1)
            .map(|node_id| NodeId::new(PrincipalId::try_from(node_id).unwrap()))
            .collect();

            let payload = ChangeSubnetMembershipPayload {
                subnet_id: subnet_id.get(),
                node_ids_add: unassigned_node_ids.clone(),
                node_ids_remove: node_ids_to_remove.clone(),
            };

            // The anonymous end-user tries to remove nodes from a subnet, bypassing the
            // proposals. This should be rejected.
            let response: Result<(), String> = registry
                .update_("change_subnet_membership", candid, (payload.clone(),))
                .await;
            assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: change_subnet_membership"));

            // .. And there should therefore be no updates to a subnet record
            let subnet_list_record = get_value_or_panic::<SubnetListRecord>(
                &registry,
                make_subnet_list_record_key().as_bytes(),
            )
            .await;
            assert_eq!(subnet_list_record.subnets.len(), 2);
            assert_eq!(subnet_list_record.subnets[1], subnet_id.get().to_vec());
            let subnet_record = get_value_or_panic::<SubnetRecord>(
                &registry,
                make_subnet_record_key(subnet_id).as_bytes(),
            )
            .await;
            assert_eq!(subnet_record.membership.len(), num_nodes_in_subnet);

            // Go through an upgrade cycle, and verify that it still works the same
            registry.upgrade_to_self_binary(vec![]).await.unwrap();
            let response: Result<(), String> = registry
                .update_("change_subnet_membership", candid, (payload.clone(),))
                .await;
            assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method:"));

            let subnet_list_record = get_value_or_panic::<SubnetListRecord>(
                &registry,
                make_subnet_list_record_key().as_bytes(),
            )
            .await;
            assert_eq!(subnet_list_record.subnets.len(), 2);
            assert_eq!(subnet_list_record.subnets[1], subnet_id.get().to_vec());
            let subnet_record = get_value_or_panic::<SubnetRecord>(
                &registry,
                make_subnet_record_key(subnet_id).as_bytes(),
            )
            .await;
            assert_eq!(subnet_record.membership.len(), num_nodes_in_subnet);

            Ok(())
        }
    });
}

#[test]
fn test_a_canister_other_than_the_governance_canister_cannot_change_subnet_membership() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            // An attacker got a canister that is trying to pass for the governance
            // canister...
            let attacker_canister = set_up_universal_canister(&runtime).await;
            // ... but thankfully, it does not have the right ID
            assert_ne!(
                attacker_canister.canister_id(),
                ic_nns_constants::GOVERNANCE_CANISTER_ID
            );

            let num_nodes_in_subnet = 4_usize;
            let (init_mutate, subnet_id, unassigned_node_ids, _) =
                prepare_registry(num_nodes_in_subnet, 3);
            let registry = set_up_registry_canister(
                &runtime,
                RegistryCanisterInitPayloadBuilder::new()
                    .push_init_mutate_request(init_mutate)
                    .build(),
            )
            .await;

            let node_ids_to_remove: Vec<NodeId> = get_value_or_panic::<SubnetRecord>(
                &registry,
                make_subnet_record_key(subnet_id).as_bytes(),
            )
            .await
            .membership
            .iter()
            .skip(1)
            .map(|node_id| NodeId::new(PrincipalId::try_from(node_id).unwrap()))
            .collect();

            let payload = ChangeSubnetMembershipPayload {
                subnet_id: subnet_id.get(),
                node_ids_add: unassigned_node_ids.clone(),
                node_ids_remove: node_ids_to_remove.clone(),
            };

            // The attacker canister tries to add nodes to a subnet, pretending to be the
            // governance canister. This should have no effect.
            assert!(
                !forward_call_via_universal_canister(
                    &attacker_canister,
                    &registry,
                    "change_subnet_membership",
                    Encode!(&payload).unwrap()
                )
                .await
            );

            let subnet_list_record = get_value_or_panic::<SubnetListRecord>(
                &registry,
                make_subnet_list_record_key().as_bytes(),
            )
            .await;
            assert_eq!(subnet_list_record.subnets.len(), 2);
            assert_eq!(subnet_list_record.subnets[1], subnet_id.get().to_vec());
            let subnet_record = get_value_or_panic::<SubnetRecord>(
                &registry,
                make_subnet_record_key(subnet_id).as_bytes(),
            )
            .await;
            assert_eq!(subnet_record.membership.len(), num_nodes_in_subnet);

            Ok(())
        }
    });
}

#[test]
fn test_change_subnet_membership_succeeds() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            let num_nodes_in_subnet = 4_usize;
            let (init_mutate, subnet_id, unassigned_node_ids, _) =
                prepare_registry(num_nodes_in_subnet, 3);

            // In order to correctly allow the subnet handler to call
            // change_subnet_membership, we must first create canisters to get
            // their IDs, and only then install them. This way, we pass the
            // initial payload to the registry so it would allow mutation by the
            // subnet handler.
            let registry = set_up_registry_canister(
                &runtime,
                RegistryCanisterInitPayloadBuilder::new()
                    .push_init_mutate_request(init_mutate)
                    .build(),
            )
            .await;

            // Get the initial node membership in the subnet
            let subnet_record = get_value_or_panic::<SubnetRecord>(
                &registry,
                make_subnet_record_key(subnet_id).as_bytes(),
            )
            .await;
            assert_eq!(subnet_record.membership.len(), 4);

            // Remove all but the first node in the subnet
            let node_ids_initial: Vec<NodeId> = get_value_or_panic::<SubnetRecord>(
                &registry,
                make_subnet_record_key(subnet_id).as_bytes(),
            )
            .await
            .membership
            .iter()
            .map(|node_id| NodeId::new(PrincipalId::try_from(node_id).unwrap()))
            .collect();
            let node_ids_to_remove = node_ids_initial[1..].to_vec();

            let payload = ChangeSubnetMembershipPayload {
                subnet_id: subnet_id.get(),
                node_ids_add: unassigned_node_ids.clone(),
                node_ids_remove: node_ids_to_remove,
            };

            // Install the universal canister in place of the governance canister
            let fake_governance_canister = set_up_universal_canister(&runtime).await;
            // Since it takes the id reserved for the governance canister, it can impersonate
            // it
            assert_eq!(
                fake_governance_canister.canister_id(),
                ic_nns_constants::GOVERNANCE_CANISTER_ID
            );

            // Ensure that the Subnet records are there
            let subnet_list_record = get_value_or_panic::<SubnetListRecord>(
                &registry,
                make_subnet_list_record_key().as_bytes(),
            )
            .await;
            assert_eq!(subnet_list_record.subnets.len(), 2);

            assert!(
                forward_call_via_universal_canister(
                    &fake_governance_canister,
                    &registry,
                    "change_subnet_membership",
                    Encode!(&payload).unwrap()
                )
                .await
            );

            // Check that the appropriate node membership in the subnet changed as expected
            let subnet_record = get_value_or_panic::<SubnetRecord>(
                &registry,
                make_subnet_record_key(subnet_id).as_bytes(),
            )
            .await;
            assert_eq!(subnet_record.membership.len(), 4);

            let node_ids_current: Vec<NodeId> = get_value_or_panic::<SubnetRecord>(
                &registry,
                make_subnet_record_key(subnet_id).as_bytes(),
            )
            .await
            .membership
            .iter()
            .map(|node_id| NodeId::new(PrincipalId::try_from(node_id).unwrap()))
            .sorted()
            .collect();

            let node_ids_expected: Vec<NodeId> = node_ids_initial
                .iter()
                .take(1)
                .cloned()
                .chain(unassigned_node_ids)
                .sorted()
                .collect();

            assert_eq!(node_ids_current, node_ids_expected);

            Ok(())
        }
    });
}

#[test]
fn test_change_subnet_membership_duplicate_nodes() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            let (init_mutate, subnet_1, subnet_2, _nodes, _) =
                prepare_registry_with_two_node_sets(3, 1, true);

            let subnet_2 = subnet_2.unwrap();

            let registry = set_up_registry_canister(
                &runtime,
                RegistryCanisterInitPayloadBuilder::new()
                    .push_init_mutate_request(init_mutate)
                    .build(),
            )
            .await;

            let mut subnet_nodes: BTreeMap<_, Vec<_>> = BTreeMap::new();
            // Get the initial node membership in the subnet
            for subnet_id in [&subnet_1, &subnet_2] {
                let subnet_record = get_value_or_panic::<SubnetRecord>(
                    &registry,
                    make_subnet_record_key(*subnet_id).as_bytes(),
                )
                .await;

                let principals: Vec<_> = subnet_record
                    .membership
                    .iter()
                    .map(|principal| PrincipalId::try_from(principal).unwrap())
                    .collect();

                subnet_nodes.insert(subnet_id, principals);
            }

            // This payload attempts to add a node from subnet 1
            // to subnet 2, while it is still a member of subnet 1.
            // It should fail because of the invariant checks.
            let payload = ChangeSubnetMembershipPayload {
                subnet_id: subnet_2.get(),
                node_ids_add: vec![NodeId::new(
                    *subnet_nodes.get(&subnet_1).unwrap().first().unwrap(),
                )],
                node_ids_remove: vec![NodeId::new(
                    *subnet_nodes.get(&subnet_2).unwrap().first().unwrap(),
                )],
            };

            // Install the universal canister in place of the governance canister
            let fake_governance_canister = set_up_universal_canister(&runtime).await;
            // Since it takes the id reserved for the governance canister, it can impersonate
            // it
            assert_eq!(
                fake_governance_canister.canister_id(),
                ic_nns_constants::GOVERNANCE_CANISTER_ID
            );

            assert!(
                !forward_call_via_universal_canister(
                    &fake_governance_canister,
                    &registry,
                    "change_subnet_membership",
                    Encode!(&payload).unwrap()
                )
                .await
            );

            // Remove two nodes from subnet 1 and assign to subnet 2
            let nodes_to_remove: Vec<_> = subnet_nodes
                .get(&subnet_1)
                .unwrap()
                .iter()
                .take(2)
                .map(|n| NodeId::new(*n))
                .collect();

            // This payload removes two nodes from the subnet 1 in order to later
            // add them to subnet 2.
            let payload = ChangeSubnetMembershipPayload {
                subnet_id: subnet_1.get(),
                node_ids_remove: nodes_to_remove.clone(),
                node_ids_add: vec![],
            };

            // Remove two nodes from subnet_1
            assert!(
                forward_call_via_universal_canister(
                    &fake_governance_canister,
                    &registry,
                    "change_subnet_membership",
                    Encode!(&payload).unwrap()
                )
                .await
            );

            // This payload adds the two removed nodes from subnet 1.
            let payload = ChangeSubnetMembershipPayload {
                subnet_id: subnet_2.get(),
                node_ids_add: nodes_to_remove.clone(),
                node_ids_remove: vec![],
            };

            // Add two nodes to subnet_2
            assert!(
                forward_call_via_universal_canister(
                    &fake_governance_canister,
                    &registry,
                    "change_subnet_membership",
                    Encode!(&payload).unwrap()
                )
                .await
            );

            for (id, expected_num_nodes) in [(subnet_1, 1), (subnet_2, 3)] {
                let subnet_record = get_value_or_panic::<SubnetRecord>(
                    &registry,
                    make_subnet_record_key(id).as_bytes(),
                )
                .await;

                assert_eq!(subnet_record.membership.len(), expected_num_nodes);
            }

            Ok(())
        }
    });
}
