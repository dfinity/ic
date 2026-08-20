use itertools::Itertools;
use std::{collections::BTreeMap, convert::TryFrom};

use assert_matches::assert_matches;

use candid::{Decode, Encode, Principal};
use canister_test::PrincipalId;
use dfn_candid::candid;
use ic_base_types::NodeId;
use ic_nervous_system_integration_tests::pocket_ic_helpers::nns::registry::decode_registry_value;
use ic_nns_constants::{
    ENGINE_CONTROLLER_CANISTER_ID, GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID,
};
use ic_nns_test_utils::{
    itest_helpers::{
        forward_call_via_universal_canister, set_up_registry_canister, set_up_universal_canister,
        state_machine_test_on_nns_subnet,
    },
    registry::{
        INITIAL_MUTATION_ID, get_value_or_panic, invariant_compliant_mutation_as_atomic_req,
        prepare_registry, prepare_registry_with_two_node_sets,
    },
};
use ic_protobuf::registry::{
    node::v1::{NodeRecord, NodeRewardType},
    subnet::v1::{SubnetListRecord, SubnetRecord},
};
use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
use pocket_ic::PocketIcBuilder;
use pocket_ic::RejectResponse;
use pocket_ic::nonblocking::PocketIc;
use registry_canister::{
    init::RegistryCanisterInitPayloadBuilder,
    mutations::do_change_subnet_membership::ChangeSubnetMembershipPayload,
};

mod common;

use common::test_helpers::{
    install_registry_canister_with_payload_builder, prepare_registry_with_cloud_engine_subnet,
    prepare_registry_with_nodes_from_template,
};

#[test]
fn test_the_anonymous_user_cannot_change_subnet_membership() {
    state_machine_test_on_nns_subnet(|runtime| {
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
    state_machine_test_on_nns_subnet(|runtime| {
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
    state_machine_test_on_nns_subnet(|runtime| {
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
    state_machine_test_on_nns_subnet(|runtime| {
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

/// Sets up a `PocketIc` with the registry canister installed, containing a
/// CloudEngine subnet plus one extra unassigned type-4 node that can be
/// swapped into the subnet.
async fn setup_cloud_engine_registry() -> (PocketIc, Principal, NodeId, NodeId) {
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;

    let (cloud_engine_mutate, cloud_engine_subnet_id) =
        prepare_registry_with_cloud_engine_subnet(4, INITIAL_MUTATION_ID);

    // Prepare an extra unassigned type-4 node to swap into the subnet.
    // Type-4 is required because the CloudEngine subnet invariant enforces
    // that all members are type-4 nodes.
    let extra_node_template = NodeRecord {
        node_operator_id: PrincipalId::new_user_test_id(999).into_vec(),
        node_reward_type: Some(NodeRewardType::Type4 as i32),
        ..Default::default()
    };
    // Use a starting mutation id well outside the range consumed by the
    // CloudEngine setup so IPs / test ids do not collide.
    let (extra_node_mutate, extra_node_ids_and_pks) = prepare_registry_with_nodes_from_template(
        1,
        INITIAL_MUTATION_ID + 100,
        extra_node_template,
    );
    let extra_node_id = *extra_node_ids_and_pks
        .keys()
        .next()
        .expect("expected one extra unassigned node");

    // Any current member of the CloudEngine subnet can be picked as the one
    // to remove; take the first one from the subnet record.
    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0));
    builder.push_init_mutate_request(cloud_engine_mutate);
    builder.push_init_mutate_request(extra_node_mutate);
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    // Read a current member of the CloudEngine subnet to use as the removal
    // target.
    let subnet_record = decode_registry_value::<SubnetRecord>(
        &pocket_ic,
        make_subnet_record_key(cloud_engine_subnet_id),
    )
    .await;
    let member_to_remove = NodeId::from(
        PrincipalId::try_from(subnet_record.membership.first().unwrap().as_slice()).unwrap(),
    );

    (
        pocket_ic,
        cloud_engine_subnet_id.get().0,
        extra_node_id,
        member_to_remove,
    )
}

#[tokio::test]
async fn test_engine_controller_can_change_membership_of_cloud_engine_subnet() {
    let (pocket_ic, cloud_engine_subnet_id, node_to_add, node_to_remove) =
        setup_cloud_engine_registry().await;

    let payload = ChangeSubnetMembershipPayload {
        subnet_id: PrincipalId::from(cloud_engine_subnet_id),
        node_ids_add: vec![node_to_add],
        node_ids_remove: vec![node_to_remove],
    };

    // The engine controller performs a 1-for-1 swap on the CloudEngine subnet.
    // This is expected to succeed.
    let response: Vec<u8> = pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            ENGINE_CONTROLLER_CANISTER_ID.get().0,
            "change_subnet_membership",
            Encode!(&payload).unwrap(),
        )
        .await
        .unwrap();
    Decode!(&response, ()).unwrap();

    // Verify the membership actually changed.
    let subnet_record = decode_registry_value::<SubnetRecord>(
        &pocket_ic,
        make_subnet_record_key(ic_base_types::SubnetId::from(PrincipalId::from(
            cloud_engine_subnet_id,
        ))),
    )
    .await;
    let members = subnet_record
        .membership
        .iter()
        .map(|bytes| NodeId::from(PrincipalId::try_from(bytes.as_slice()).unwrap()))
        .collect::<Vec<NodeId>>();
    assert!(
        members.contains(&node_to_add),
        "swapped-in node {node_to_add} should now be a subnet member, got {members:?}"
    );
    assert!(
        !members.contains(&node_to_remove),
        "swapped-out node {node_to_remove} should no longer be a subnet member, got {members:?}"
    );
}

#[tokio::test]
async fn test_engine_controller_cannot_change_membership_of_non_cloud_engine_subnet() {
    // Set up a registry that contains only the invariant-compliant system
    // subnet (which is not a CloudEngine).
    let pocket_ic = PocketIcBuilder::new().with_nns_subnet().build_async().await;
    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(0));
    install_registry_canister_with_payload_builder(&pocket_ic, builder.build(), true).await;

    // Identify the (only) non-CloudEngine subnet.
    let subnet_list =
        decode_registry_value::<SubnetListRecord>(&pocket_ic, make_subnet_list_record_key()).await;
    let non_cloud_engine_subnet =
        Principal::try_from(subnet_list.subnets.first().unwrap().as_slice()).unwrap();

    let payload = ChangeSubnetMembershipPayload {
        subnet_id: PrincipalId::from(non_cloud_engine_subnet),
        node_ids_add: vec![],
        node_ids_remove: vec![],
    };

    // First, establish that this payload is itself valid by having governance
    // (which is exempt from the CloudEngine restriction) successfully apply
    // it as a no-op change against the non-CloudEngine subnet.
    let response: Vec<u8> = pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            GOVERNANCE_CANISTER_ID.get().0,
            "change_subnet_membership",
            Encode!(&payload).unwrap(),
        )
        .await
        .unwrap();
    Decode!(&response, ()).unwrap();

    // Now the engine controller submits the exact same payload; since the
    // target subnet is not a CloudEngine, the call must be rejected.
    let response: Result<Vec<u8>, RejectResponse> = pocket_ic
        .update_call(
            REGISTRY_CANISTER_ID.get().0,
            ENGINE_CONTROLLER_CANISTER_ID.get().0,
            "change_subnet_membership",
            Encode!(&payload).unwrap(),
        )
        .await;

    let err = response.unwrap_err();
    assert!(
        err.reject_message
            .contains("may only change membership of CloudEngine subnets"),
        "expected a CloudEngine-specific rejection message, got {err:?}"
    );
}
