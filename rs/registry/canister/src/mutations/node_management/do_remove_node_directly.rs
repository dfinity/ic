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
use ic_registry_keys::{make_api_boundary_node_record_key, make_subnet_record_key};

impl Registry {
    /// Removes an existing node from the registry.
    ///
    /// This method is called directly by the node operator tied to the node.
    pub fn do_remove_node_directly(&mut self, payload: RemoveNodeDirectlyPayload) {
        let caller_id = dfn_core::api::caller();
        println!(
            "{}do_remove_node_directly started: {:?} caller: {:?}",
            LOG_PREFIX, payload, caller_id
        );
        self.do_remove_node(payload, caller_id);
    }

    pub fn do_remove_node(&mut self, payload: RemoveNodeDirectlyPayload, caller_id: PrincipalId) {
        // 1. Find the node operator id for this record
        // and abort if the node record is not found
        let node_operator_id = get_node_operator_id_for_node(self, payload.node_id)
            .map_err(|e| {
                format!(
                    "{}do_remove_node_directly: Aborting node removal: {}",
                    LOG_PREFIX, e
                )
            })
            .unwrap();

        // 2. Compare the caller_id (node operator) with the node's node operator and, if that fails,
        // fall back to comparing the node provider ID of the caller and the node's node provider ID.
        if caller_id != node_operator_id {
            let node_provider_caller = get_node_provider_id_for_operator_id(self, caller_id)
                .map_err(|e| {
                    format!(
                        "{}do_remove_node_directly: Aborting node removal: {}",
                        LOG_PREFIX, e
                    )
                });
            let node_provider_of_the_node =
                get_node_provider_id_for_operator_id(self, node_operator_id).map_err(|e| {
                    format!(
                        "{}do_remove_node_directly: Aborting node removal: {}",
                        LOG_PREFIX, e
                    )
                });
            assert_eq!(
                node_provider_caller, node_provider_of_the_node,
                "The node provider {:?} of the caller {}, does not match the node provider {:?} of the node {}.",
                node_provider_caller, caller_id, node_provider_of_the_node, payload.node_id
            );
        }

        // 3. Ensure node is not in a subnet
        let subnet_list_record = get_subnet_list_record(self);
        let is_node_in_subnet = find_subnet_for_node(self, payload.node_id, &subnet_list_record);
        if let Some(subnet_id) = is_node_in_subnet {
            panic!("{}do_remove_node_directly: Cannot remove a node that is a member of a subnet. This node is a member of Subnet: {}",
                LOG_PREFIX,
                make_subnet_record_key(subnet_id)
            );
        }

        // 4. Ensure the node is not an API Boundary Node.
        // In order to succeed, a corresponding ApiBoundaryNodeRecord should be removed first via proposal.
        let api_bn_id = self.get_api_boundary_node_record(payload.node_id);
        if api_bn_id.is_some() {
            panic!(
                "{}do_remove_node_directly: Cannot remove a node, as it has ApiBoundaryNodeRecord with record_key: {}",
                LOG_PREFIX,
                make_api_boundary_node_record_key(payload.node_id)
            );
        }

        // 5. Retrieve the NO record and increment its node allowance by 1
        let mut new_node_operator_record = get_node_operator_record(self, caller_id)
            .map_err(|err| {
                format!(
                    "{}do_remove_node_directly: Aborting node removal: {}",
                    LOG_PREFIX, err
                )
            })
            .unwrap();
        new_node_operator_record.node_allowance += 1;

        // 6. Finally, generate the following mutations:
        //   * Delete the node
        //   * Delete entries for node encryption keys
        //   * Increment NO's allowance by 1
        let mut mutations = make_remove_node_registry_mutations(self, payload.node_id);
        // mutation to update node operator value
        mutations.push(make_update_node_operator_mutation(
            node_operator_id,
            &new_node_operator_record,
        ));

        // 7. Apply mutations after checking invariants
        self.maybe_apply_mutation_internal(mutations);

        println!(
            "{}do_remove_node_directly finished: {:?}",
            LOG_PREFIX, payload
        );
    }
}

/// The payload of an update request to remove a node.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize)]
pub struct RemoveNodeDirectlyPayload {
    pub node_id: NodeId,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ic_base_types::PrincipalId;
    use ic_protobuf::registry::{
        api_boundary_node::v1::ApiBoundaryNodeRecord, node_operator::v1::NodeOperatorRecord,
    };
    use ic_registry_keys::make_node_operator_record_key;
    use ic_registry_transport::insert;
    use ic_types::ReplicaVersion;
    use prost::Message;

    use crate::{
        common::test_helpers::{
            invariant_compliant_registry, prepare_registry_with_nodes,
            prepare_registry_with_nodes_and_node_operator_id,
        },
        mutations::common::test::TEST_NODE_ID,
    };

    use super::*;

    #[test]
    #[should_panic(expected = "Node Id 2vxsx-fae not found in the registry")]
    fn should_panic_if_node_is_not_found() {
        let mut registry = invariant_compliant_registry(0);
        let node_operator_id = PrincipalId::from_str(TEST_NODE_ID).unwrap();
        let node_id = NodeId::from(node_operator_id);
        let payload = RemoveNodeDirectlyPayload { node_id };

        registry.do_remove_node(payload, node_operator_id);
    }

    #[test]
    #[should_panic(expected = "Cannot remove a node, as it has ApiBoundaryNodeRecord")]
    fn should_panic_if_node_is_api_boundary_node() {
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
        // Add API BN to registry
        let api_bn = ApiBoundaryNodeRecord {
            version: ReplicaVersion::default().to_string(),
        };
        registry.maybe_apply_mutation_internal(vec![insert(
            make_api_boundary_node_record_key(node_id),
            api_bn.encode_to_vec(),
        )]);
        let payload = RemoveNodeDirectlyPayload { node_id };

        registry.do_remove_node(payload, node_operator_id);
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
        let payload = RemoveNodeDirectlyPayload { node_id };

        registry.do_remove_node(payload, node_operator_id);
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

        registry.do_remove_node(payload, operator2_id);
    }

    #[test]
    fn should_succeed_remove_node_compare_node_provider() {
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

        // Should succeed because both operator1 and operator2 are under the same provider
        registry.do_remove_node(payload, operator2_id);
    }
}
