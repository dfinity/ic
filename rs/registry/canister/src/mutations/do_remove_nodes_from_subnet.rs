use crate::{common::LOG_PREFIX, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::NodeId;
use ic_nns_common::registry::get_subnet_ids_from_subnet_list;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_transport::update;
use prost::Message;
use serde::Serialize;

impl Registry {
    /// Remove nodes from their subnets
    pub fn do_remove_nodes_from_subnet(&mut self, payload: RemoveNodesFromSubnetPayload) {
        println!("{LOG_PREFIX}do_remove_nodes_from_subnet started: {payload:?}");

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
                        make_subnet_record_key(subnet_id).as_bytes(),
                        subnet.encode_to_vec(),
                    ))
                } else {
                    None
                }
            })
            .collect();

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);

        println!("{LOG_PREFIX}do_remove_nodes_from_subnet finished: {payload:?}");
    }
}

/// The payload of a proposal to remove a Node from a Subnet
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct RemoveNodesFromSubnetPayload {
    /// The list of Node IDs that will be removed from their subnet
    pub node_ids: Vec<NodeId>,
}
