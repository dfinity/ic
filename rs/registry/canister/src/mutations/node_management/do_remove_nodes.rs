use crate::mutations::node_management::common::{
    find_subnet_for_node, get_node_operator_id_for_node, get_node_operator_record,
    get_subnet_list_record,
};
use crate::{common::LOG_PREFIX, registry::Registry};
use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::NodeId;
use ic_nns_common::registry::encode_or_panic;
use ic_registry_keys::{
    make_node_operator_record_key, make_node_record_key, make_subnet_record_key,
};
use ic_registry_transport::{delete, update};
use serde::Serialize;
use std::collections::HashMap;

impl Registry {
    /// Removes an existing node from the registry.
    pub fn do_remove_nodes(&mut self, payload: RemoveNodesPayload) {
        println!("{}do_remove_nodes: {:?}", LOG_PREFIX, payload);

        // This hashmap tracks node operators for which mutations have already been
        // determined; increments to node allowance should not be idempotent
        let mut node_operator_hmap = HashMap::<String, u64>::new();

        // 1. De-duplicate the node list
        let mut nodes_to_be_removed = payload.node_ids;
        nodes_to_be_removed.sort_unstable();
        nodes_to_be_removed.dedup();

        // 2. Retrieve the Subnet List to ensure no subnets contain each of the nodes

        let subnet_list_record = get_subnet_list_record(self);

        // 3. Loop through each node
        let mutations = nodes_to_be_removed
            .into_iter().flat_map(|node_to_remove| {

                // 4. Find the node operator id for this record
                // and abort if the node record is not found
                let node_operator_id = get_node_operator_id_for_node(self, node_to_remove)
                    .map_err(|e| format!("{}do_remove_nodes: Aborting node removal: {}", LOG_PREFIX, e))
                    .unwrap();

                // 5. Ensure node is not in a subnet 
                let is_node_in_subnet = find_subnet_for_node(self, node_to_remove, &subnet_list_record);
                if let Some(subnet_id) = is_node_in_subnet {
                    panic!("{}do_remove_nodes: Cannot remove a node that is a member of a subnet. This node is a member of Subnet: {}",
                        LOG_PREFIX,
                        make_subnet_record_key(subnet_id)
                    );
                }

                // 6. Retrieve the NO record and increment its node allowance by 1
                let mut new_node_operator_record = get_node_operator_record(self, node_operator_id)
                    .map_err(|err| {
                        format!(
                            "{}do_remove_nodes: Aborting node removal: {}",
                            LOG_PREFIX, err
                        )
                    })
                    .unwrap();

                let node_operator_key = make_node_operator_record_key(node_operator_id);

                // Use the hashmap to track whether the same NO has already been mutated in the same call
                new_node_operator_record.node_allowance = match node_operator_hmap.get(&node_operator_key) {
                    Some(n) => {
                        *n + 1
                    }
                    None => {
                        new_node_operator_record.node_allowance + 1
                    }
                };
                node_operator_hmap.insert(node_operator_key.clone(), new_node_operator_record.node_allowance);

                // 7. Finally, generate the following mutations:
                //   * Delete the node
                //   * Increment NO's allowance by 1
                let node_key = make_node_record_key(node_to_remove);
                vec![
                    delete(node_key),
                    update(
                        node_operator_key,
                        encode_or_panic(&new_node_operator_record),
                    ),
                ]
        }).collect();

        // 8. Apply mutations after checking invariants
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of an update request to add a new node.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RemoveNodesPayload {
    /// The list of Node IDs that will be removed
    pub node_ids: Vec<NodeId>,
}
