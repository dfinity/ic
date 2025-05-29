use crate::{common::LOG_PREFIX, registry::Registry};
use ic_base_types::NodeId;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_registry_keys::make_node_record_key;
use ic_registry_transport::pb::v1::RegistryValue;
use prost::Message;

impl Registry {
    /// Get the Node record or panic on error with a message.
    pub fn get_node_or_panic(&self, node_id: NodeId) -> NodeRecord {
        self.get_node(node_id).unwrap_or_else(|| {
            panic!(
                "{}node record for {:} not found in the registry.",
                LOG_PREFIX, node_id
            );
        })
    }

    /// Get the Node record if it exists in the Registry.
    pub fn get_node(&self, node_id: NodeId) -> Option<NodeRecord> {
        let reg_value: RegistryValue = self.get(
            &make_node_record_key(node_id).into_bytes(),
            self.latest_version(),
        )?;

        Some(NodeRecord::decode(reg_value.value.as_slice()).unwrap())
    }
}
