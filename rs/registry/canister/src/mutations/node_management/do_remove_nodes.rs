use crate::mutations::node_management::common::{
    find_subnet_for_node, get_node_operator_id_for_node, get_node_operator_record,
    get_subnet_list_record, make_remove_node_registry_mutations,
    make_update_node_operator_mutation,
};
use crate::{common::LOG_PREFIX, registry::Registry};
use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::NodeId;
use ic_registry_keys::make_subnet_record_key;
use serde::Serialize;
use std::collections::HashMap;

impl Registry {
    /// Removes an existing node from the registry.
    pub fn do_remove_nodes(&mut self, payload: RemoveNodesPayload) {
        println!("{LOG_PREFIX}do_remove_nodes started: {payload:?}");

        // This hashmap tracks node operators for which mutations have already been
        // determined; increments to node allowance should not be idempotent
        let mut node_operator_hmap = HashMap::<String, u64>::new();

        // 1. De-duplicate the node list
        let mut nodes_to_be_removed = payload.node_ids.clone();
        nodes_to_be_removed.sort_unstable();
        nodes_to_be_removed.dedup();

        // 2. Retrieve the Subnet List to ensure no subnets contain each of the nodes

        let subnet_list_record = get_subnet_list_record(self);

        // 3. Loop through each node
        let mutations = nodes_to_be_removed
            .into_iter().flat_map(|node_to_remove| {
                // 4. Skip nodes that are not in the registry.
                // This tackles the race condition where a node is removed from the registry
                // by another transaction before this transaction is processed.
                if self.get_node(node_to_remove).is_none() {
                    println!("{LOG_PREFIX}do_remove_nodes: node {node_to_remove} not found in registry, skipping");
                    return vec![];
                };

                // 5. Find the node operator id for this record
                // and abort if the node record is not found
                let node_operator_id = get_node_operator_id_for_node(self, node_to_remove)
                    .map_err(|e| format!("{LOG_PREFIX}do_remove_nodes: Aborting node removal: {e}"))
                    .unwrap();

                // 6. Ensure node is not in a subnet
                let is_node_in_subnet = find_subnet_for_node(self, node_to_remove, &subnet_list_record);
                if let Some(subnet_id) = is_node_in_subnet {
                    panic!("{}do_remove_nodes: Cannot remove a node that is a member of a subnet. This node is a member of Subnet: {}",
                        LOG_PREFIX,
                        make_subnet_record_key(subnet_id)
                    );
                }

                // 7. Retrieve the NO record and increment its node allowance by 1
                let mut new_node_operator_record = get_node_operator_record(self, node_operator_id)
                    .map_err(|err| {
                        format!(
                            "{LOG_PREFIX}do_remove_nodes: Aborting node removal: {err}"
                        )
                    })
                    .unwrap();

                // Use the hashmap to track whether the same NO has already been mutated in the same call
                new_node_operator_record.node_allowance = match node_operator_hmap.get(&node_operator_id.to_string()) {
                    Some(n) => {
                        *n + 1
                    }
                    None => {
                        new_node_operator_record.node_allowance + 1
                    }
                };
                node_operator_hmap.insert(node_operator_id.to_string(), new_node_operator_record.node_allowance);

                // 8. Finally, generate the following mutations:
                //   * Delete the node
                //   * Delete entries for node encryption keys
                //   * Increment NO's allowance by 1
                let mut mutations = make_remove_node_registry_mutations(self, node_to_remove);
                // mutation to update node operator value
                mutations.push(make_update_node_operator_mutation(
                    node_operator_id,
                    &new_node_operator_record,
                ));

                mutations
        }).collect();

        // 8. Apply mutations after checking invariants
        self.maybe_apply_mutation_internal(mutations);

        println!("{LOG_PREFIX}do_remove_nodes finished: {payload:?}");
    }
}

/// The payload of an update request to remove some nodes.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct RemoveNodesPayload {
    /// The list of Node IDs that will be removed
    pub node_ids: Vec<NodeId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::test_helpers::{invariant_compliant_registry, prepare_registry_with_nodes};
    use ic_base_types::PrincipalId;
    use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
    use ic_registry_keys::{make_node_operator_record_key, make_node_record_key};
    use ic_registry_transport::insert;
    use prost::Message;

    #[test]
    fn test_remove_nonexistent_node() {
        let mut registry = invariant_compliant_registry(0);

        let nonexistent_node_id = NodeId::from(PrincipalId::new_user_test_id(999));
        let payload = RemoveNodesPayload {
            node_ids: vec![nonexistent_node_id],
        };

        // Should not panic, just skip the nonexistent node
        registry.do_remove_nodes(payload);
    }

    #[test]
    fn test_remove_single_node() {
        let mut registry = invariant_compliant_registry(0);

        // Add a node to the registry
        let (mutate_request, node_ids) = prepare_registry_with_nodes(1, 1);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let node_id = *node_ids.keys().next().unwrap();
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id).node_operator_id).unwrap();

        // Allow this node operator to onboard 1 more node; the initial value is not important in this test.
        // We just want to later see that node_allowance gets incremented by `do_remove_nodes`.
        let initial_allowance = 1;
        let node_operator_record = NodeOperatorRecord {
            node_allowance: initial_allowance,
            ..Default::default()
        };

        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);

        // Remove the node
        let payload = RemoveNodesPayload {
            node_ids: vec![node_id],
        };
        registry.do_remove_nodes(payload);
        // Verify node is removed
        assert!(
            registry
                .get(
                    make_node_record_key(node_id).as_bytes(),
                    registry.latest_version()
                )
                .is_none()
        );

        // Verify node operator allowance was incremented
        let updated_operator = get_node_operator_record(&registry, node_operator_id).unwrap();
        assert_eq!(updated_operator.node_allowance, initial_allowance + 1);
    }
    #[test]
    fn test_remove_multiple_nodes_same_operator() {
        let mut registry = invariant_compliant_registry(0);

        // Add multiple nodes to the registry
        let (mutate_request, node_ids) = prepare_registry_with_nodes(1, 3);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let node_ids: Vec<NodeId> = node_ids.keys().cloned().collect();
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_ids[0]).node_operator_id)
                .unwrap();

        // Add node operator record
        let initial_allowance = 0;
        let node_operator_record = NodeOperatorRecord {
            node_allowance: initial_allowance,
            ..Default::default()
        };

        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);

        // Remove two nodes
        let payload = RemoveNodesPayload {
            node_ids: node_ids[..2].to_vec(),
        };

        registry.do_remove_nodes(payload);

        // Verify the two nodes are removed
        for node_id in &node_ids[..2] {
            assert!(
                registry
                    .get(
                        make_node_record_key(*node_id).as_bytes(),
                        registry.latest_version()
                    )
                    .is_none()
            );
        }

        // Verify the third node is still present
        assert!(registry.get_node(node_ids[2]).is_some());

        // Verify node operator allowance was incremented by 2
        let updated_operator = get_node_operator_record(&registry, node_operator_id).unwrap();
        assert_eq!(updated_operator.node_allowance, initial_allowance + 2);
    }

    #[test]
    fn test_remove_duplicate_and_nonexistent_node_ids() {
        let mut registry = invariant_compliant_registry(0);

        // Add a node to the registry
        let (mutate_request, node_ids) = prepare_registry_with_nodes(1, 1);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let node_id = node_ids.keys().next().unwrap().to_owned();
        let node_operator_id =
            PrincipalId::try_from(registry.get_node_or_panic(node_id).node_operator_id).unwrap();

        // Add node operator record
        let initial_allowance = 0;
        let node_operator_record = NodeOperatorRecord {
            node_allowance: initial_allowance,
            ..Default::default()
        };

        registry.maybe_apply_mutation_internal(vec![insert(
            make_node_operator_record_key(node_operator_id),
            node_operator_record.encode_to_vec(),
        )]);

        // Try to remove the same node multiple times
        let payload = RemoveNodesPayload {
            node_ids: vec![
                node_id,
                NodeId::from(PrincipalId::new_node_test_id(111)),
                node_id,
                NodeId::from(PrincipalId::new_node_test_id(222)),
                node_id,
            ],
        };

        registry.do_remove_nodes(payload);

        // Verify node is removed
        assert!(
            registry
                .get(
                    make_node_record_key(node_id).as_bytes(),
                    registry.latest_version()
                )
                .is_none()
        );

        // Verify other node_ids are still in the registry
        for other_node_id in node_ids.keys().skip(1) {
            assert!(registry.get_node(*other_node_id).is_some());
        }

        // Verify node operator allowance was incremented only once
        let updated_operator = get_node_operator_record(&registry, node_operator_id).unwrap();
        assert_eq!(updated_operator.node_allowance, initial_allowance + 1);
    }
}
