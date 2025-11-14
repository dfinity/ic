use crate::mutations::node_management::common::{
    find_subnet_for_node, get_node_operator_id_for_node, get_node_operator_record,
    get_node_provider_id_for_operator_id, get_subnet_list_record,
    make_remove_node_registry_mutations, make_update_node_operator_mutation,
};
use crate::{common::LOG_PREFIX, registry::Registry};
use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{NodeId, PrincipalId};
use ic_nervous_system_time_helpers::now_system_time;
use ic_registry_keys::{make_api_boundary_node_record_key, make_subnet_record_key};
use ic_registry_transport::pb::v1::RegistryMutation;
use ic_registry_transport::{delete, insert, upsert};
use prost::Message;
use std::time::SystemTime;

impl Registry {
    /// Removes an existing node from the registry.
    ///
    /// This method is called directly by the node operator tied to the node.
    pub fn do_remove_node_directly(&mut self, payload: RemoveNodeDirectlyPayload) {
        let caller_id = dfn_core::api::caller();
        println!("{LOG_PREFIX}do_remove_node_directly started: {payload:?} caller: {caller_id:?}");
        self.do_remove_node_directly_(payload.clone(), caller_id, now_system_time())
            .unwrap();

        println!("{LOG_PREFIX}do_remove_node_directly finished: {payload:?}");
    }

    #[cfg(test)]
    fn do_replace_node_with_another(
        &mut self,
        payload: RemoveNodeDirectlyPayload,
        caller_id: PrincipalId,
        new_node_id: NodeId,
    ) {
        let mutations =
            self.make_remove_or_replace_node_mutations(payload, caller_id, Some(new_node_id));

        // Check invariants and apply mutations
        self.maybe_apply_mutation_internal(mutations);
    }

    fn do_remove_node_directly_(
        &mut self,
        payload: RemoveNodeDirectlyPayload,
        caller_id: PrincipalId,
        now: SystemTime,
    ) -> Result<(), String> {
        // Get the node operator ID for this node
        let node_operator_id = get_node_operator_id_for_node(self, payload.node_id)?;
        let reservation =
            self.try_reserve_capacity_for_node_operator_operation(now, node_operator_id, 1)?;

        let mutations = self.make_remove_or_replace_node_mutations(payload, caller_id, None);
        // Check invariants and apply mutations
        self.maybe_apply_mutation_internal(mutations);

        if let Err(e) = self.commit_used_capacity_for_node_operator_operation(now, reservation) {
            println!("{LOG_PREFIX}Error committing Rate Limit usage: {e}");
        }

        Ok(())
    }

    // Prepare mutations for removing or replacing a node in the registry.
    // * If new_node_id is Some, the old node is in-place replaced with the new node, even if the old node is
    //   in active use (i.e., assigned to a subnet or acts as an API boundary node).
    // * If new_node_id is None, the old node is only removed from the registry and is not allowed to be in active use.
    pub fn make_remove_or_replace_node_mutations(
        &mut self,
        payload: RemoveNodeDirectlyPayload,
        caller_id: PrincipalId,
        new_node_id: Option<NodeId>,
    ) -> Vec<RegistryMutation> {
        // 1. Find the node operator id for this record
        // and abort if the node record is not found
        let node_operator_id = get_node_operator_id_for_node(self, payload.node_id)
            .map_err(|e| format!("{LOG_PREFIX}do_remove_node_directly: Aborting node removal: {e}"))
            .unwrap();

        // 2. Compare the caller_id (node operator) with the node's node operator and, if that fails,
        // fall back to comparing the DC and the node provider ID for the caller and the node.
        // That covers the case when the node provider added a new operator record in the same DC, and
        // is trying to redeploy the nodes under the new operator.
        // Hence, if the DC and the node provider of the caller and the original node operator match,
        // the removal should succeed.
        if caller_id != node_operator_id {
            let node_operator_caller = get_node_operator_record(self, caller_id)
                .map_err(|e| {
                    format!("{LOG_PREFIX}do_remove_node_directly: Aborting node removal: {e}")
                })
                .unwrap();
            let dc_caller = node_operator_caller.dc_id;
            let dc_orig_node_operator = get_node_operator_record(self, node_operator_id)
                .map_err(|e| {
                    format!("{LOG_PREFIX}do_remove_node_directly: Aborting node removal: {e}")
                })
                .unwrap()
                .dc_id;
            assert_eq!(
                dc_caller, dc_orig_node_operator,
                "The DC {dc_caller} of the caller {caller_id}, does not match the DC of the node {dc_orig_node_operator}."
            );
            let node_provider_caller = get_node_provider_id_for_operator_id(self, caller_id)
                .map_err(|e| {
                    format!("{LOG_PREFIX}do_remove_node_directly: Aborting node removal: {e}")
                });
            let node_provider_of_the_node =
                get_node_provider_id_for_operator_id(self, node_operator_id).map_err(|e| {
                    format!("{LOG_PREFIX}do_remove_node_directly: Aborting node removal: {e}")
                });
            assert_eq!(
                node_provider_caller, node_provider_of_the_node,
                "The node provider {:?} of the caller {}, does not match the node provider {:?} of the node {}.",
                node_provider_caller, caller_id, node_provider_of_the_node, payload.node_id
            );
        }

        let mut mutations = vec![];

        // 3. Check if the node is an API Boundary Node. If there is a replacement node, remove the existing node
        //    and try to assign the new one to act as API boundary node. This will only work if the new node meets all
        //    the requirements of an API boundary node (e.g., it is configured with a domain name).
        if let Some(api_bn_record) = self.get_api_boundary_node_record(payload.node_id) {
            let Some(replacement_node_id) = new_node_id else {
                panic!(
                    "{}do_remove_node_directly: Cannot remove this node, as it is an active API boundary node: {}",
                    LOG_PREFIX,
                    make_api_boundary_node_record_key(payload.node_id)
                );
            };

            // remove the existing API boundary node record
            let old_key = make_api_boundary_node_record_key(payload.node_id);
            mutations.push(delete(old_key));

            // create the new API boundary node record by just cloning the old one and inserting it with the new key
            let new_key = make_api_boundary_node_record_key(replacement_node_id);
            mutations.push(insert(new_key, api_bn_record.clone().encode_to_vec()));
        }

        // 4. Check if node is in a subnet, and if so, replace it in the subnet by updating the membership in the subnet record.
        let subnet_list_record = get_subnet_list_record(self);
        let is_node_in_subnet = find_subnet_for_node(self, payload.node_id, &subnet_list_record);
        // Disabled until the direct replacement of nodes that are active in a subnet is possible.
        let replacements_of_nodes_in_subnets_enabled = false;
        if let Some(subnet_id) = is_node_in_subnet {
            if let Some(new_node_id) = new_node_id
                && replacements_of_nodes_in_subnets_enabled
            {
                // The node is in a subnet and is being replaced with a new node.
                // Update the subnet record with the new node membership.
                let mut subnet_record = self.get_subnet_or_panic(subnet_id);

                let mut subnet_membership: Vec<NodeId> = subnet_record
                    .membership
                    .iter()
                    .map(|bytes| NodeId::from(PrincipalId::try_from(bytes).unwrap()))
                    .collect();

                subnet_membership.retain(|&id| id != payload.node_id);
                subnet_membership.push(new_node_id);

                // Update the subnet record with the new membership (and double check that the new node is not in a subnet)
                self.replace_subnet_record_membership(
                    subnet_id,
                    &mut subnet_record,
                    subnet_membership,
                );
                mutations.push(upsert(
                    make_subnet_record_key(subnet_id),
                    subnet_record.encode_to_vec(),
                ));
            } else {
                panic!(
                    "{}do_remove_node_directly: Cannot remove a node that is a member of a subnet. This node is a member of Subnet: {}",
                    LOG_PREFIX,
                    make_subnet_record_key(subnet_id)
                );
            }
        }

        // 5. Retrieve the NO record and increment its node allowance by 1
        let mut updated_node_operator_record = get_node_operator_record(self, node_operator_id)
            .map_err(|err| {
                format!("{LOG_PREFIX}do_remove_node_directly: Aborting node removal: {err}")
            })
            .unwrap();
        updated_node_operator_record.node_allowance += 1;

        // 6. Finally, generate the following mutations:
        //   * Delete the node record
        //   * Delete entries for node encryption keys
        //   * Increment NO's allowance by 1
        mutations.extend(make_remove_node_registry_mutations(self, payload.node_id));
        // mutation to update node operator value
        mutations.push(make_update_node_operator_mutation(
            node_operator_id,
            &updated_node_operator_record,
        ));

        mutations
    }
}

/// The payload of an update request to remove a node.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct RemoveNodeDirectlyPayload {
    pub node_id: NodeId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::prepare_registry_with_nodes_and_node_operator_id;
    use crate::mutations::do_add_node_operator::AddNodeOperatorPayload;
    use crate::{
        common::test_helpers::{
            invariant_compliant_registry, prepare_registry_with_nodes,
            registry_add_node_operator_for_node, registry_create_subnet_with_nodes,
        },
        mutations::common::test::TEST_NODE_ID,
    };
    use ic_base_types::{NodeId, PrincipalId};
    use ic_protobuf::registry::node::v1::NodeRewardType;
    use ic_protobuf::registry::{
        api_boundary_node::v1::ApiBoundaryNodeRecord, node_operator::v1::NodeOperatorRecord,
    };
    use ic_registry_keys::{make_node_operator_record_key, make_node_record_key};
    use ic_registry_transport::{insert, update};
    use ic_types::ReplicaVersion;
    use maplit::btreemap;
    use prost::Message;
    use std::str::FromStr;

    /// Returns Registry, NodeId, node operator id, node principal id
    fn setup_registry_for_test() -> (Registry, Vec<NodeId>, PrincipalId, PrincipalId) {
        let mut registry = invariant_compliant_registry(0);

        // Add node to registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(
            1, // mutation id
            2, // node count
        );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let node_ids: Vec<NodeId> = node_ids_and_dkg_pks.keys().cloned().collect();
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_ids[0]).node_operator_id)
                .expect("failed to get the node operator id");

        let node_provider_id = PrincipalId::new_user_test_id(20_002);

        let payload = AddNodeOperatorPayload {
            node_operator_principal_id: Some(node_operator_id),
            node_provider_principal_id: Some(node_provider_id),
            dc_id: "DC1".to_string(),
            ipv6: Some("bar".to_string()),
            ..Default::default()
        };

        registry.do_add_node_operator(payload);

        (registry, node_ids, node_operator_id, node_provider_id)
    }

    #[test]
    #[should_panic(expected = "Node Id 2vxsx-fae not found in the registry")]
    fn should_panic_if_node_is_not_found() {
        let mut registry = invariant_compliant_registry(0);
        let node_operator_id = PrincipalId::from_str(TEST_NODE_ID).unwrap();
        let node_id = NodeId::from(node_operator_id);
        let payload = RemoveNodeDirectlyPayload { node_id };

        registry
            .do_remove_node_directly_(payload, node_operator_id, now_system_time())
            .expect("failed to do remove node directly");
    }

    #[test]
    #[should_panic(expected = "Cannot remove this node, as it is an active API boundary node")]
    fn should_panic_if_node_is_api_boundary_node_and_no_replacement() {
        let (mut registry, node_ids, node_operator_id, _) = setup_registry_for_test();
        let node_id = node_ids[0];

        // Add API BN to registry
        let api_bn = ApiBoundaryNodeRecord {
            version: ReplicaVersion::default().to_string(),
        };
        registry.maybe_apply_mutation_internal(vec![insert(
            make_api_boundary_node_record_key(node_id),
            api_bn.encode_to_vec(),
        )]);
        let payload = RemoveNodeDirectlyPayload { node_id };

        let _ = registry.do_remove_node_directly_(payload, node_operator_id, now_system_time());
    }

    #[test]
    fn should_succeed_to_replace_api_boundary_node() {
        let (mut registry, node_ids, node_operator_id, _) = setup_registry_for_test();
        let old_node_id = node_ids[0];
        let new_node_id = node_ids[1];

        // turn first node into an API BN by adding the record to the registry
        let api_bn = ApiBoundaryNodeRecord {
            version: ReplicaVersion::default().to_string(),
        };
        registry.maybe_apply_mutation_internal(vec![insert(
            make_api_boundary_node_record_key(old_node_id),
            api_bn.encode_to_vec(),
        )]);
        let payload = RemoveNodeDirectlyPayload {
            node_id: old_node_id,
        };

        registry.do_replace_node_with_another(payload, node_operator_id, new_node_id);

        // Verify the removed node's API boundary node record has been removed
        assert!(
            registry
                .get(
                    make_api_boundary_node_record_key(old_node_id).as_bytes(),
                    registry.latest_version()
                )
                .is_none()
        );

        // Verify the replacement node has been turned into an API boundary node
        assert!(
            registry
                .get(
                    make_api_boundary_node_record_key(new_node_id).as_bytes(),
                    registry.latest_version()
                )
                .is_some()
        );

        // Verify the old node is removed from the registry
        assert!(
            registry
                .get(
                    make_node_record_key(old_node_id).as_bytes(),
                    registry.latest_version()
                )
                .is_none()
        );

        // Verify the new node is present in the registry
        assert!(registry.get_node(new_node_id).is_some());

        // Verify node operator allowance set to 1
        let updated_operator = get_node_operator_record(&registry, node_operator_id).unwrap();
        assert_eq!(updated_operator.node_allowance, 1);
    }

    #[test]
    #[should_panic(
        expected = "invariant check failed with message: domain field of the NodeRecord"
    )]
    fn should_panic_to_replace_api_boundary_node_if_new_node_has_no_domain() {
        let (mut registry, node_ids, node_operator_id, _) = setup_registry_for_test();
        let old_node_id = node_ids[0];
        let new_node_id = node_ids[1];

        // turn first node into an API BN by adding the record to the registry
        let api_bn = ApiBoundaryNodeRecord {
            version: ReplicaVersion::default().to_string(),
        };
        registry.maybe_apply_mutation_internal(vec![insert(
            make_api_boundary_node_record_key(old_node_id),
            api_bn.encode_to_vec(),
        )]);

        // remove the default domain name from the replacement node such that the API boundary node invariant check fails
        let mut node_record = registry.get_node_or_panic(new_node_id);
        node_record.domain = None;
        let update_node_record = update(
            make_node_record_key(new_node_id).as_bytes(),
            node_record.encode_to_vec(),
        );
        let mutations = vec![update_node_record];
        registry.maybe_apply_mutation_internal(mutations);

        let payload = RemoveNodeDirectlyPayload {
            node_id: old_node_id,
        };

        registry.do_replace_node_with_another(payload, node_operator_id, new_node_id);
    }

    #[test]
    fn should_succeed() {
        let mut registry = invariant_compliant_registry(0);
        // Add node to registry
        let (mutate_request, node_ids_and_dkg_pks) =
            prepare_registry_with_nodes(1 /* mutation id */, 1 /* node count */);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("should contain at least one node ID")
            .to_owned();
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id).node_operator_id).unwrap();
        // Add node operator record
        let node_operator_record = NodeOperatorRecord::default();
        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);
        let original_node_operator_record =
            get_node_operator_record(&registry, node_operator_id).unwrap();
        let expected_node_operator_record = NodeOperatorRecord {
            node_allowance: original_node_operator_record.node_allowance + 1,
            ..original_node_operator_record
        };

        let payload = RemoveNodeDirectlyPayload { node_id };

        let _ = registry.do_remove_node_directly_(payload, node_operator_id, now_system_time());
        let actual_node_operator_record =
            get_node_operator_record(&registry, node_operator_id).unwrap();
        assert_eq!(expected_node_operator_record, actual_node_operator_record);
    }

    #[test]
    #[should_panic(
        expected = "assertion `left == right` failed: The node provider Ok(5yckv-7nzbm-aaaaa-aaaap-4ai) of the caller ziab2-3ora4-aaaaa-aaaap-4ai, does not match the node provider Ok(ahdmd-q5ybm-aaaaa-aaaap-4ai) of the node"
    )]
    fn should_panic_different_caller() {
        // This test is only added for backward compatibility.
        // It should be removed once all tests are updated to include operator record.
        let mut registry = invariant_compliant_registry(0);
        let operator1_id = PrincipalId::new_user_test_id(2000);
        let operator2_id = PrincipalId::new_user_test_id(2001);
        let operator_record_1 = NodeOperatorRecord {
            node_operator_principal_id: operator1_id.to_vec(),
            node_provider_principal_id: PrincipalId::new_user_test_id(3000).to_vec(),
            dc_id: "dc1".to_string(),
            node_allowance: 1,
            ..Default::default()
        };
        let operator_record_2 = NodeOperatorRecord {
            node_operator_principal_id: operator2_id.to_vec(),
            node_provider_principal_id: PrincipalId::new_user_test_id(3001).to_vec(),
            dc_id: "dc1".to_string(),
            node_allowance: 1,
            ..Default::default()
        };
        registry.maybe_apply_mutation_internal(vec![
            insert(
                make_node_operator_record_key(operator1_id),
                operator_record_1.encode_to_vec(),
            ),
            insert(
                make_node_operator_record_key(operator2_id),
                operator_record_2.encode_to_vec(),
            ),
        ]);
        // Add node owned by operator1 to registry
        let (mutate_request, node_ids_and_dkg_pks) =
            prepare_registry_with_nodes_and_node_operator_id(
                1, /* mutation id */
                1, /* node count */
                operator1_id,
            );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("should contain at least one node ID")
            .to_owned();

        let payload = RemoveNodeDirectlyPayload { node_id };

        let _ = registry.do_remove_node_directly_(payload, operator2_id, now_system_time());
    }

    #[test]
    fn should_succeed_remove_node_compare_dc_and_node_provider() {
        let mut registry = invariant_compliant_registry(0);
        // Add node operator1 and operator2 records, both under the same provider
        let operator1_id = PrincipalId::new_user_test_id(2000);
        let operator2_id = PrincipalId::new_user_test_id(2001);
        let operator_record_1 = NodeOperatorRecord {
            node_operator_principal_id: operator1_id.to_vec(),
            node_provider_principal_id: PrincipalId::new_user_test_id(3000).to_vec(),
            dc_id: "dc1".to_string(),
            node_allowance: 1,
            rewardable_nodes: btreemap! { "type0".to_string() => 0, "type1".to_string() => 28 },
            ..Default::default()
        };
        let operator_record_2 = NodeOperatorRecord {
            node_operator_principal_id: operator2_id.to_vec(),
            node_provider_principal_id: PrincipalId::new_user_test_id(3000).to_vec(),
            dc_id: "dc1".to_string(),
            node_allowance: 1,
            rewardable_nodes: btreemap! { "type1.1".to_string() => 28 },
            ..Default::default()
        };
        registry.maybe_apply_mutation_internal(vec![
            insert(
                make_node_operator_record_key(operator1_id),
                operator_record_1.encode_to_vec(),
            ),
            insert(
                make_node_operator_record_key(operator2_id),
                operator_record_2.encode_to_vec(),
            ),
        ]);
        // Add node owned by operator1 to registry
        let (mutate_request, node_ids_and_dkg_pks) =
            prepare_registry_with_nodes_and_node_operator_id(
                1, /* mutation id */
                1, /* node count */
                operator1_id,
            );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("should contain at least one node ID")
            .to_owned();
        let original_operator_record_1 =
            get_node_operator_record(&registry, operator1_id).expect("failed to get node operator");
        let original_operator_record_2 =
            get_node_operator_record(&registry, operator2_id).expect("failed to get node operator");

        let payload = RemoveNodeDirectlyPayload { node_id };

        // Should succeed because both operator1 and operator2 are under the same provider
        let _ = registry.do_remove_node_directly_(payload, operator2_id, now_system_time());

        let expected_operator_record_1 = NodeOperatorRecord {
            node_allowance: original_operator_record_1.node_allowance + 1,
            ..original_operator_record_1
        };
        let expected_operator_record_2 = NodeOperatorRecord {
            node_allowance: original_operator_record_2.node_allowance,
            ..original_operator_record_2
        };
        let actual_operator_record_1 =
            get_node_operator_record(&registry, operator1_id).expect("failed to get node operator");
        println!("node_operator_1_record: {actual_operator_record_1:#?}");
        let actual_operator_record_2 =
            get_node_operator_record(&registry, operator2_id).expect("failed to get node operator");
        println!("node_operator_2_record: {actual_operator_record_2:#?}");

        assert_eq!(actual_operator_record_1, expected_operator_record_1);
        assert_eq!(actual_operator_record_2, expected_operator_record_2);
    }

    #[test]
    #[should_panic(
        expected = "assertion `left == right` failed: The DC not-dc1 of the caller ziab2-3ora4-aaaaa-aaaap-4ai, does not match the DC of the node dc1."
    )]
    fn should_panic_remove_node_different_dc() {
        let mut registry = invariant_compliant_registry(0);
        // Add node operator1 and operator2 records, both under the same provider
        let operator1_id = PrincipalId::new_user_test_id(2000);
        let operator2_id = PrincipalId::new_user_test_id(2001);
        let operator_record_1 = NodeOperatorRecord {
            node_operator_principal_id: operator1_id.to_vec(),
            node_provider_principal_id: PrincipalId::new_user_test_id(3000).to_vec(),
            dc_id: "dc1".to_string(),
            node_allowance: 1,
            ..Default::default()
        };
        let operator_record_2 = NodeOperatorRecord {
            node_operator_principal_id: operator2_id.to_vec(),
            node_provider_principal_id: PrincipalId::new_user_test_id(3000).to_vec(),
            dc_id: "not-dc1".to_string(),
            node_allowance: 1,
            ..Default::default()
        };
        registry.maybe_apply_mutation_internal(vec![
            insert(
                make_node_operator_record_key(operator1_id),
                operator_record_1.encode_to_vec(),
            ),
            insert(
                make_node_operator_record_key(operator2_id),
                operator_record_2.encode_to_vec(),
            ),
        ]);
        // Add node owned by operator1 to registry
        let (mutate_request, node_ids_and_dkg_pks) =
            prepare_registry_with_nodes_and_node_operator_id(
                1, /* mutation id */
                1, /* node count */
                operator1_id,
            );
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_id = node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("should contain at least one node ID")
            .to_owned();

        let payload = RemoveNodeDirectlyPayload { node_id };

        // Should fail because the DC of operator1 and operator2 does not match
        let _ = registry.do_remove_node_directly_(payload, operator2_id, now_system_time());
    }

    #[test]
    #[should_panic(expected = "Cannot remove a node that is a member of a subnet")]
    fn should_panic_if_removing_node_in_subnet_without_replacement() {
        let mut registry = invariant_compliant_registry(0);

        // Add nodes to the registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 1);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_ids: Vec<NodeId> = node_ids_and_dkg_pks.keys().cloned().collect();
        let node_operator_id = registry_add_node_operator_for_node(
            &mut registry,
            node_ids[0],
            btreemap! { NodeRewardType::Type1 => 1 },
        );

        // Create a subnet with the first node
        let _subnet_id =
            registry_create_subnet_with_nodes(&mut registry, &node_ids_and_dkg_pks, &[0]);

        // Attempt to remove the node without replacement
        let payload = RemoveNodeDirectlyPayload {
            node_id: node_ids[0],
        };

        let _ = registry.do_remove_node_directly_(payload, node_operator_id, now_system_time());
    }

    // This test is disabled until it becomes possible to directly replace nodes that are active in a subnet.
    #[ignore]
    #[test]
    fn should_replace_node_in_subnet_and_update_allowance() {
        let mut registry = invariant_compliant_registry(0);

        // Add nodes to the registry
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 2);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);
        let node_ids = node_ids_and_dkg_pks.keys().cloned().collect::<Vec<_>>();
        let node_operator_id = registry_add_node_operator_for_node(
            &mut registry,
            node_ids[0],
            btreemap! { NodeRewardType::Type1 => 1 },
        );

        // Create a subnet with the first node
        let subnet_id =
            registry_create_subnet_with_nodes(&mut registry, &node_ids_and_dkg_pks, &[0]);

        // Replace the first node with the second node in the subnet
        let payload = RemoveNodeDirectlyPayload {
            node_id: node_ids[0],
        };

        registry.do_replace_node_with_another(payload, node_operator_id, node_ids[1]);

        // Verify the subnet record is updated with the new node
        let expected_membership: Vec<NodeId> = vec![node_ids[1]];
        let actual_membership: Vec<NodeId> = registry
            .get_subnet_or_panic(subnet_id)
            .membership
            .iter()
            .map(|bytes| NodeId::from(PrincipalId::try_from(bytes).unwrap()))
            .collect();
        assert_eq!(actual_membership, expected_membership);

        // Verify the old node is removed from the registry
        assert!(
            registry
                .get(
                    make_node_record_key(node_ids[0]).as_bytes(),
                    registry.latest_version()
                )
                .is_none()
        );

        // Verify the new node is present in the registry
        assert!(registry.get_node(node_ids[1]).is_some());

        // Verify node operator allowance increased by 1
        let updated_operator = get_node_operator_record(&registry, node_operator_id).unwrap();
        assert_eq!(updated_operator.node_allowance, 1);
    }

    #[test]
    fn test_do_remove_node_directly_fails_when_rate_limits_exceeded() {
        let (mut registry, node_ids, node_operator_id, node_provider_id) =
            setup_registry_for_test();
        let node_id = node_ids[0];

        let now = now_system_time();

        let payload = RemoveNodeDirectlyPayload { node_id };

        // Exhaust the rate limit capacity
        let available_operator =
            registry.get_available_node_operator_op_capacity(node_operator_id, now);
        let available_provider =
            registry.get_available_node_provider_op_capacity(node_provider_id, now);
        let available = available_operator.min(available_provider);
        let reservation = registry
            .try_reserve_capacity_for_node_operator_operation(now, node_operator_id, available)
            .unwrap();
        registry
            .commit_used_capacity_for_node_operator_operation(now, reservation)
            .unwrap();

        let error = registry
            .do_remove_node_directly_(payload, node_operator_id, now)
            .unwrap_err();
        assert_eq!(
            error,
            "Rate Limit Capacity exceeded. Please wait and try again later."
        );
    }
}
