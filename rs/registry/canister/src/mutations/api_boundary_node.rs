use crate::{common::LOG_PREFIX, registry::Registry};

use ic_base_types::NodeId;
use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
use ic_registry_keys::make_api_boundary_node_record_key;
use ic_registry_transport::pb::v1::RegistryValue;
use prost::Message;

impl Registry {
    /// Get the ApiBoundaryNode record
    pub fn get_api_boundary_node_record(&self, node_id: NodeId) -> Option<ApiBoundaryNodeRecord> {
        let RegistryValue {
            value: api_boundary_node_record_vec,
            version: _,
            deletion_marker: _,
        } = self.get(
            &make_api_boundary_node_record_key(node_id).into_bytes(),
            self.latest_version(),
        )?;

        Some(ApiBoundaryNodeRecord::decode(api_boundary_node_record_vec.as_slice()).unwrap())
    }

    /// Get the ApiBoundaryNode record or panic on error with a message.
    pub fn get_api_boundary_node_or_panic(&self, node_id: NodeId) -> ApiBoundaryNodeRecord {
        self.get_api_boundary_node_record(node_id)
            .unwrap_or_else(|| {
                panic!(
                    "{}api_boundary_node record for {:} not found in the registry.",
                    LOG_PREFIX, node_id
                )
            })
    }
}
