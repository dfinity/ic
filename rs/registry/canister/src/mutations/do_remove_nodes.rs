use crate::{common::LOG_PREFIX, mutations::common::decode_registry_value, registry::Registry};

use std::{collections::HashMap, convert::TryFrom};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_nns_common::registry::encode_or_panic;
use ic_protobuf::registry::{
    node::v1::NodeRecord,
    node_operator::v1::NodeOperatorRecord,
    subnet::v1::{SubnetListRecord, SubnetRecord},
};
use ic_registry_keys::{
    make_node_operator_record_key, make_node_record_key, make_subnet_list_record_key,
    make_subnet_record_key,
};
use ic_registry_transport::{delete, pb::v1::RegistryValue, update};

impl Registry {
    /// Removes an existing node from the registry.
    pub fn do_remove_nodes(&mut self, payload: RemoveNodesPayload) {
        println!("{}do_remove_node: {:?}", LOG_PREFIX, payload);

        // This hashmap tracks node operators for which mutations have already been
        // determined; increments to node allowance should not be idempotent
        let mut node_operator_hmap = HashMap::<String, u64>::new();

        // 1. De-duplicate the node list
        let mut nodes_to_be_removed = payload.node_ids;
        nodes_to_be_removed.sort_unstable();
        nodes_to_be_removed.dedup();

        // 2. Retrieve the Subnet List to ensure no subnets contain each of the nodes
        let RegistryValue {
            value: subnet_list_record_vec,
            version: _,
            deletion_marker: _,
        } = self
            .get(
                make_subnet_list_record_key().as_bytes(),
                self.latest_version(),
            )
            .map_or(
                Err(format!(
                "{}do_remove_node: Subnet List not found in the registry, aborting node removal.",
                LOG_PREFIX)),
                Ok,
            )
            .unwrap();

        let subnet_list_record =
            decode_registry_value::<SubnetListRecord>(subnet_list_record_vec.to_vec());

        // 3. Loop through each node
        let mutations = nodes_to_be_removed
            .into_iter()
            .map(|node_to_remove| {
                // 4. Check that the specified node record exists
                let node_key = make_node_record_key(node_to_remove);
                let RegistryValue {
                    value: node_record,
                    version: _,
                    deletion_marker: _,
                } = self
                    .get(node_key.as_bytes(), self.latest_version())
                    .map_or(
                        Err(format!(
                        "{}do_remove_node: Node Id {:} not found in the registry, aborting node removal.",
                        LOG_PREFIX, node_to_remove)),
                        Ok,
                    )
                    .unwrap();

                // 5. Check if the node is in a Subnet
                let is_node_in_subnet = subnet_list_record
                    .subnets
                    .iter()
                    .find(|subnet_id| -> bool {
                        let subnet_key = make_subnet_record_key(SubnetId::new(
                                PrincipalId::try_from(*subnet_id).unwrap(),
                            ));

                        let RegistryValue {
                            value: subnet_record_vec,
                            version: _,
                            deletion_marker: _,
                        } = self
                            .get(
                                subnet_key.as_bytes(),
                                self.latest_version(),
                            )
                            .map_or(
                                Err(format!(
                                    "{}do_remove_node: Subnet not found in the registry, aborting node removal.",
                                    LOG_PREFIX)),
                                Ok,
                            )
                            .unwrap();

                        let subnet_record =
                            decode_registry_value::<SubnetRecord>(subnet_record_vec.to_vec());

                        subnet_record.membership.contains(&node_to_remove.get().to_vec())
                    });

                if let Some(subnet_id) = is_node_in_subnet {
                    panic!("{}do_remove_node: Cannot remove a node that is a member of a subnet. This node is a member of Subnet: {}",
                        LOG_PREFIX,
                        make_subnet_record_key(SubnetId::new(PrincipalId::try_from(subnet_id).unwrap()))
                    );
                }

                // 6. Retrieve the NO record and increment its node allowance by 1
                let node_operator_key = make_node_operator_record_key(
                    PrincipalId::try_from(
                        decode_registry_value::<NodeRecord>(node_record.to_vec()).node_operator_id,
                    )
                    .unwrap(),
                );
                let RegistryValue {
                    value: node_operator_record,
                    version: _,
                    deletion_marker: _,
                } = self
                    .get(node_operator_key.as_bytes(), self.latest_version())
                    .map_or(Err(format!(
                        "{}do_remove_node: Node Operator Id {:} not found in the registry, aborting node removal.",
                        LOG_PREFIX, node_operator_key)), Ok).unwrap();

                let mut new_node_operator_record =
                    decode_registry_value::<NodeOperatorRecord>(node_operator_record.to_vec());

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

                // 7. Lastly, return the following mutations:
                //   * Delete the node
                //   * Increment NO's allowance by 1
                vec![
                    delete(node_key),
                    update(
                        node_operator_key,
                        encode_or_panic(&new_node_operator_record),
                    ),
                ]
        }).flatten().collect();

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of an update request to add a new node.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RemoveNodesPayload {
    /// The list of Node IDs that will be removed
    pub node_ids: Vec<NodeId>,
}
