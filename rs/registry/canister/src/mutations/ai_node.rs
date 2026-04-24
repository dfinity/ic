use std::str::FromStr;

use crate::{
    common::{LOG_PREFIX, key_family::get_key_family_iter},
    registry::Registry,
};

use ic_base_types::NodeId;
use ic_protobuf::registry::ai_node::v1::AiNodeRecord;
use ic_registry_keys::{AI_NODE_RECORD_KEY_PREFIX, make_ai_node_record_key};
use ic_registry_transport::pb::v1::RegistryValue;
use ic_types::PrincipalId;
use prost::Message;

impl Registry {
    /// Get the AiNode record
    pub fn get_ai_node_record(&self, node_id: NodeId) -> Option<AiNodeRecord> {
        let RegistryValue {
            value: ai_node_record_vec,
            version: _,
            deletion_marker: _,
            timestamp_nanoseconds: _,
        } = self.get(
            &make_ai_node_record_key(node_id).into_bytes(),
            self.latest_version(),
        )?;

        Some(AiNodeRecord::decode(ai_node_record_vec.as_slice()).unwrap())
    }

    /// Get the AiNode record or panic on error with a message.
    pub fn get_ai_node_or_panic(&self, node_id: NodeId) -> AiNodeRecord {
        self.get_ai_node_record(node_id).unwrap_or_else(|| {
            panic!("{LOG_PREFIX}ai_node record for {node_id:} not found in the registry.")
        })
    }

    /// Get all AI node IDs.
    pub fn get_ai_node_ids(&self) -> Result<Vec<NodeId>, String> {
        let mut err_ids = Vec::new();

        let ids: Vec<NodeId> = get_key_family_iter::<AiNodeRecord>(self, AI_NODE_RECORD_KEY_PREFIX)
            .filter_map(|(id_str, _)| match PrincipalId::from_str(&id_str) {
                Ok(principal_id) => Some(NodeId::from(principal_id)),
                Err(_) => {
                    err_ids.push(id_str);
                    None
                }
            })
            .collect();

        if err_ids.is_empty() {
            Ok(ids)
        } else {
            let err_msg = format!(
                "The following AI node IDs couldn't be parsed from registry: [{}]",
                err_ids.join(", ")
            );
            Err(err_msg)
        }
    }
}
