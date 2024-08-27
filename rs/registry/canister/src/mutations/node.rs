use crate::{common::LOG_PREFIX, registry::Registry};
use ic_base_types::NodeId;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_registry_keys::make_node_record_key;
use ic_registry_transport::pb::v1::RegistryValue;
use prost::Message;

impl Registry {
    /// Get the Node record or panic on error with a message.
    pub fn get_node_or_panic(&self, node_id: NodeId) -> NodeRecord {
        let RegistryValue {
            value: node_record_vec,
            version: _,
            deletion_marker: _,
        } = self
            .get(
                &make_node_record_key(node_id).into_bytes(),
                self.latest_version(),
            )
            .unwrap_or_else(|| {
                panic!(
                    "{}node record for {:} not found in the registry.",
                    LOG_PREFIX, node_id
                )
            });

        NodeRecord::decode(node_record_vec.as_slice()).unwrap()
    }
}
