use std::convert::TryFrom;

use assert_matches::assert_matches;

use candid::Encode;
use canister_test::PrincipalId;
use dfn_candid::candid;
use ic_base_types::{NodeId, SubnetId};
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, local_test_on_nns_subnet, set_up_registry_canister,
        set_up_universal_canister,
    },
    registry::{get_value, prepare_registry, prepare_registry_with_two_node_sets},
};
use ic_protobuf::registry::subnet::v1::{SubnetListRecord, SubnetRecord};
use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_remove_nodes_from_subnet::RemoveNodesFromSubnetPayload,
};

#[test]
fn test_the_anonymous_user_cannot_remove_nodes_from_subnet() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            let num_nodes_in_subnet = 4_usize;
            let (init_mutate, subnet_id, _, _) = prepare_registry(num_nodes_in_subnet, 0);
            let mut registry = set_up_registry_canister(
                &runtime,
                RegistryCanisterInitPayloadBuilder::new()
                    .push_init_mutate_request(init_mutate)
                    .build(),
            )
            .await;

            let node_ids_to_remove =
                get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                    .await
                    .membership
                    .iter()
                    .map(|node_id| NodeId::new(PrincipalId::try_from(node_id).unwrap()))
                    .collect();

            let payload = RemoveNodesFromSubnetPayload {
                node_ids: node_ids_to_remove,
            };

            // The anonymous end-user tries to remove nodes from a subnet, bypassing the
            // proposals. This should be rejected.
            let response: Result<(), String> = registry
                .update_("remove_nodes_from_subnet", candid, (payload.clone(),))
                .await;
            assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: remove_nodes_from_subnet"));

            // .. And there should therefore be no updates to a subnet record
            let subnet_list_record =
                get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                    .await;
            assert_eq!(subnet_list_record.subnets.len(), 2);
            assert_eq!(subnet_list_record.subnets[1], subnet_id.get().to_vec());
            let subnet_record =
                get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                    .await;
            assert_eq!(subnet_record.membership.len(), num_nodes_in_subnet);

            // Go through an upgrade cycle, and verify that it still works the same
            registry.upgrade_to_self_binary(vec![]).await.unwrap();
            let response: Result<(), String> = registry
                .update_("remove_nodes_from_subnet", candid, (payload.clone(),))
                .await;
            assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method:"));

            let subnet_list_record =
                get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                    .await;
            assert_eq!(subnet_list_record.subnets.len(), 2);
            assert_eq!(subnet_list_record.subnets[1], subnet_id.get().to_vec());
            let subnet_record =
                get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                    .await;
            assert_eq!(subnet_record.membership.len(), num_nodes_in_subnet);

            Ok(())
        }
    });
}

#[test]
fn test_a_canister_other_than_the_proposals_canister_cannot_remove_nodes_from_subnet() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            // An attacker got a canister that is trying to pass for the proposals
            // canister...
            let attacker_canister = set_up_universal_canister(&runtime).await;
            // ... but thankfully, it does not have the right ID
            assert_ne!(
                attacker_canister.canister_id(),
                ic_nns_constants::GOVERNANCE_CANISTER_ID
            );

            let num_nodes_in_subnet = 4_usize;
            let (init_mutate, subnet_id, _, _) = prepare_registry(num_nodes_in_subnet, 0);
            let registry = set_up_registry_canister(
                &runtime,
                RegistryCanisterInitPayloadBuilder::new()
                    .push_init_mutate_request(init_mutate)
                    .build(),
            )
            .await;

            let node_ids_to_remove =
                get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                    .await
                    .membership
                    .iter()
                    .map(|node_id| NodeId::new(PrincipalId::try_from(node_id).unwrap()))
                    .collect();

            let payload = RemoveNodesFromSubnetPayload {
                node_ids: node_ids_to_remove,
            };

            // The attacker canister tries to add nodes to a subnet, pretending to be the
            // proposals canister. This should have no effect.
            assert!(
                !forward_call_via_universal_canister(
                    &attacker_canister,
                    &registry,
                    "remove_nodes_from_subnet",
                    Encode!(&payload).unwrap()
                )
                .await
            );

            let subnet_list_record =
                get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                    .await;
            assert_eq!(subnet_list_record.subnets.len(), 2);
            assert_eq!(subnet_list_record.subnets[1], subnet_id.get().to_vec());
            let subnet_record =
                get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                    .await;
            assert_eq!(subnet_record.membership.len(), num_nodes_in_subnet);

            Ok(())
        }
    });
}

#[test]
fn test_remove_nodes_from_subnet_succeeds() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            let num_nodes_in_subnet1 = 4_usize;
            let num_nodes_in_subnet2 = 4_usize;
            let (init_mutate, subnet1_id, subnet2_node_ids, _) =
                prepare_registry_with_two_node_sets(
                    num_nodes_in_subnet1,
                    num_nodes_in_subnet2,
                    true,
                );

            // In order to correctly allow the subnet handler to call
            // remove_nodes_from_subnet, we must first create canisters to get
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

            // Install the universal canister in place of the proposals canister
            let fake_proposal_canister = set_up_universal_canister(&runtime).await;
            // Since it takes the id reserved for the proposal canister, it can impersonate
            // it
            assert_eq!(
                fake_proposal_canister.canister_id(),
                ic_nns_constants::GOVERNANCE_CANISTER_ID
            );

            // Ensure that the Subnet records are there
            let subnet_list_record =
                get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                    .await;
            assert_eq!(subnet_list_record.subnets.len(), 3);

            let subnet_record =
                get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet1_id).as_bytes())
                    .await;

            // Remove all but the first node in each subnet
            let node_ids_to_remove = subnet_record
                .membership
                .into_iter()
                .skip(1)
                .map(|node_id| NodeId::new(PrincipalId::try_from(node_id).unwrap()))
                .chain(subnet2_node_ids.into_iter().skip(1))
                .collect();

            let payload = RemoveNodesFromSubnetPayload {
                node_ids: node_ids_to_remove,
            };

            assert!(
                forward_call_via_universal_canister(
                    &fake_proposal_canister,
                    &registry,
                    "remove_nodes_from_subnet",
                    Encode!(&payload).unwrap()
                )
                .await
            );

            // Check that both Subnets lost all of their nodes
            let subnet1_record =
                get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet1_id).as_bytes())
                    .await;
            assert_eq!(subnet1_record.membership.len(), 1);
            let subnet2_record = get_value::<SubnetRecord>(
                &registry,
                make_subnet_record_key(SubnetId::new(
                    PrincipalId::try_from(subnet_list_record.subnets[2].clone()).unwrap(),
                ))
                .as_bytes(),
            )
            .await;
            assert_eq!(subnet2_record.membership.len(), 1);

            Ok(())
        }
    });
}

/// Check that nodes unassigned to a subnet cannot be removed using
/// `remove_nodes_from_subnet`
#[test]
fn test_removing_unassigned_nodes_from_subnet_does_nothing() {
    local_test_on_nns_subnet(|runtime| {
        async move {
            let num_nodes_in_subnet = 2_usize;
            let num_unassigned_nodes = 2_usize;
            let (init_mutate, subnet_id, unassigned_node_ids, _) =
                prepare_registry(num_nodes_in_subnet, num_unassigned_nodes);

            // In order to correctly allow the subnet handler to call atomic_mutate, we
            // must first create canisters to get their IDs, and only then install them.
            // This way, we pass the initial payload to the registry so it would allow
            // mutation by the subnet handler.
            let registry = set_up_registry_canister(
                &runtime,
                RegistryCanisterInitPayloadBuilder::new()
                    .push_init_mutate_request(init_mutate)
                    .build(),
            )
            .await;

            // Install the universal canister in place of the proposals canister
            let fake_proposal_canister = set_up_universal_canister(&runtime).await;
            // Since it takes the id reserved for the proposal canister, it can impersonate
            // it
            assert_eq!(
                fake_proposal_canister.canister_id(),
                ic_nns_constants::GOVERNANCE_CANISTER_ID
            );

            // Ensure that the subnet record is there
            let subnet_list_record =
                get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                    .await;
            assert_eq!(subnet_list_record.subnets.len(), 2);
            assert_eq!(subnet_list_record.subnets[1], subnet_id.get().to_vec());
            let subnet_record =
                get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                    .await;
            assert_eq!(subnet_record.membership.len(), num_nodes_in_subnet as usize);

            let payload = RemoveNodesFromSubnetPayload {
                node_ids: unassigned_node_ids.clone(),
            };

            assert!(
                forward_call_via_universal_canister(
                    &fake_proposal_canister,
                    &registry,
                    "remove_nodes_from_subnet",
                    Encode!(&payload).unwrap()
                )
                .await
            );

            let subnet_list_record =
                get_value::<SubnetListRecord>(&registry, make_subnet_list_record_key().as_bytes())
                    .await;
            assert_eq!(subnet_list_record.subnets.len(), 2);
            assert_eq!(subnet_list_record.subnets[1], subnet_id.get().to_vec());
            let subnet_record =
                get_value::<SubnetRecord>(&registry, make_subnet_record_key(subnet_id).as_bytes())
                    .await;
            assert_eq!(subnet_record.membership.len(), num_nodes_in_subnet);
            for node_id in unassigned_node_ids {
                let node_id = node_id.get().to_vec();
                assert!(subnet_record.membership.iter().all(|x| *x != node_id));
            }

            Ok(())
        }
    });
}
