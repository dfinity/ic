use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::NodeId;
use ic_registry_keys::make_ai_node_record_key;
use ic_registry_transport::delete;
use serde::Serialize;

use crate::{common::LOG_PREFIX, registry::Registry};

use super::common::check_ai_nodes_exist;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct RemoveAiNodesPayload {
    pub node_ids: Vec<NodeId>,
}

impl Registry {
    /// Remove a set of AiNodeRecords from the registry
    pub fn do_remove_ai_nodes(&mut self, payload: RemoveAiNodesPayload) {
        println!("{LOG_PREFIX}do_remove_ai_nodes: {payload:?}");

        // Ensure payload is valid
        self.validate_remove_ai_nodes_payload(&payload);

        // Mutations to remove AiNodeRecords
        let mutations = payload.node_ids.into_iter().map(|node_id| {
            let key = make_ai_node_record_key(node_id);
            delete(key)
        });

        self.maybe_apply_mutation_internal(mutations.collect())
    }

    fn validate_remove_ai_nodes_payload(&self, payload: &RemoveAiNodesPayload) {
        check_ai_nodes_exist(self, &payload.node_ids);
    }
}
