use crate::{common::LOG_PREFIX, mutations::common::encode_or_panic, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use serde::Serialize;

use ic_base_types::NodeId;
use ic_registry_keys::make_node_record_key;
use ic_registry_transport::update;

impl Registry {
    pub fn do_update_nodes_hostos_version(&mut self, payload: UpdateNodesHostosVersionPayload) {
        println!("{}do_update_node_hostos_version: {:?}", LOG_PREFIX, payload);

        let mut mutations = Vec::new();
        for node_id in payload.node_ids {
            // Get the node record
            let node_key = make_node_record_key(node_id);
            let mut node_record = self.get_node_or_panic(node_id);
            node_record
                .hostos_version_id
                .clone_from(&payload.hostos_version_id);

            // Update HostOS version
            mutations.push(update(node_key, encode_or_panic(&node_record)));
        }

        // Check invariants before applying mutations
        // This will verify that the version does exist
        self.maybe_apply_mutation_internal(mutations)
    }
}

/// The argument of a command to update the HostOS version of a single
/// node to a specific version.
///
/// The record will be mutated only if the given version exists.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateNodesHostosVersionPayload {
    /// The node to update.
    pub node_ids: Vec<NodeId>,
    /// The new HostOS version to use.
    pub hostos_version_id: Option<String>,
}
