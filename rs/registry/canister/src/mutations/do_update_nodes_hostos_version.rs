use crate::{common::LOG_PREFIX, registry::Registry};

use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::NodeId;
use ic_registry_keys::make_node_record_key;
use ic_registry_transport::update;
use prost::Message;
use serde::Serialize;

impl Registry {
    pub fn do_update_nodes_hostos_version(&mut self, payload: UpdateNodesHostosVersionPayload) {
        let payload = DeployHostosToSomeNodes::from(payload);
        self.do_deploy_hostos_to_some_nodes(payload)
    }

    pub fn do_deploy_hostos_to_some_nodes(&mut self, payload: DeployHostosToSomeNodes) {
        println!(
            "{}do_deploy_hostos_to_some_nodes: {:?}",
            LOG_PREFIX, payload
        );

        let mut mutations = Vec::new();
        for node_id in payload.node_ids {
            // Get the node record
            let node_key = make_node_record_key(node_id);
            let mut node_record = self.get_node_or_panic(node_id);
            node_record
                .hostos_version_id
                .clone_from(&payload.hostos_version_id);

            // Update HostOS version
            mutations.push(update(node_key, node_record.encode_to_vec()));
        }

        // Check invariants before applying mutations
        // This will verify that the version does exist
        self.maybe_apply_mutation_internal(mutations)
    }
}

/// Deprecated; please use `DeployHostosToSomeNodes` instead.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateNodesHostosVersionPayload {
    /// The node to update.
    pub node_ids: Vec<NodeId>,
    /// The new HostOS version to use.
    pub hostos_version_id: Option<String>,
}

/// The argument of a command to update the HostOS version of a single
/// node to a specific version.
///
/// The record will be mutated only if the given version exists.
#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct DeployHostosToSomeNodes {
    /// The node to update.
    pub node_ids: Vec<NodeId>,
    /// The new HostOS version to use.
    pub hostos_version_id: Option<String>,
}

impl From<UpdateNodesHostosVersionPayload> for DeployHostosToSomeNodes {
    fn from(src: UpdateNodesHostosVersionPayload) -> Self {
        let UpdateNodesHostosVersionPayload {
            node_ids,
            hostos_version_id,
        } = src;

        Self {
            node_ids,
            hostos_version_id,
        }
    }
}
