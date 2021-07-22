use crate::{common::LOG_PREFIX, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use ic_base_types::NodeId;
use ic_nns_common::registry::{encode_or_panic, get_subnet_ids_from_subnet_list};
use ic_registry_keys::make_subnet_record_key;
use ic_registry_transport::update;

impl Registry {
    /// Remove nodes from their subnets
    pub fn do_remove_nodes_from_subnet(&mut self, payload: RemoveNodesFromSubnetPayload) {
        println!("{}do_remove_nodes_from_subnet: {:?}", LOG_PREFIX, payload);

        let mutations = get_subnet_ids_from_subnet_list(self.get_subnet_list_record())
            .into_iter()
            .map(|subnet_id| (subnet_id, self.get_subnet_or_panic(subnet_id)))
            .filter_map(|(subnet_id, mut subnet)| {
                let initial_len = subnet.membership.len();
                subnet.membership.retain(|node_id_vec| {
                    !payload
                        .node_ids
                        .iter()
                        .map(|node_to_remove| node_to_remove.get().to_vec())
                        .any(|x| &x == node_id_vec)
                });

                if initial_len != subnet.membership.len() {
                    Some(update(
                        make_subnet_record_key(subnet_id).as_bytes().to_vec(),
                        encode_or_panic(&subnet),
                    ))
                } else {
                    None
                }
            })
            .collect();

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}

/// The payload of a proposal to remove a Node from a Subnet
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RemoveNodesFromSubnetPayload {
    /// The list of Node IDs that will be removed from their subnet
    pub node_ids: Vec<NodeId>,
}
