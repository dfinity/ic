use candid::{CandidType, Deserialize};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::{NodeId, SubnetId};
use ic_registry_keys::{make_ai_node_record_key, make_subnet_record_key};
use ic_registry_transport::update;
use prost::Message;
use serde::Serialize;

use crate::{common::LOG_PREFIX, registry::Registry};

use super::common::check_ai_nodes_exist;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct UpdateAiNodeSubnetPayload {
    pub node_id: NodeId,
    /// New subnet association for the AI node. When `None`, the AI node is
    /// disassociated from any subnet.
    pub subnet_id: Option<SubnetId>,
}

impl Registry {
    /// Updates the `subnet_id` of an existing AiNodeRecord.
    pub fn do_update_ai_node_subnet(&mut self, payload: UpdateAiNodeSubnetPayload) {
        println!("{LOG_PREFIX}do_update_ai_node_subnet: {payload:?}");

        // Ensure payload is valid
        self.validate_update_ai_node_subnet_payload(&payload);

        let key = make_ai_node_record_key(payload.node_id);
        let mut ai_node = self.get_ai_node_or_panic(payload.node_id);
        ai_node.subnet_id = payload.subnet_id.map(|s| s.get().to_vec());

        self.maybe_apply_mutation_internal(vec![update(key, ai_node.encode_to_vec())]);
    }

    fn validate_update_ai_node_subnet_payload(&self, payload: &UpdateAiNodeSubnetPayload) {
        // AiNodeRecord must exist.
        check_ai_nodes_exist(self, &[payload.node_id]);

        // If a subnet_id is provided, it must exist in the registry.
        if let Some(subnet_id) = payload.subnet_id {
            let key = make_subnet_record_key(subnet_id);
            if self.get(key.as_bytes(), self.latest_version()).is_none() {
                panic!("subnet {subnet_id} does not exist");
            }
        }
    }
}
