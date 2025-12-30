use crate::{common::LOG_PREFIX, registry::Registry};
use ic_base_types::{NodeId, PrincipalId};
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::{make_node_operator_record_key, make_node_record_key};
use ic_registry_transport::pb::v1::RegistryValue;
use prost::Message;

impl Registry {
    /// Get the Node record or panic on error with a message.
    pub fn get_node_or_panic(&self, node_id: NodeId) -> NodeRecord {
        self.get_node(node_id).unwrap_or_else(|| {
            panic!("{LOG_PREFIX}node record for {node_id:} not found in the registry.");
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

    pub fn get_node_operator_or_panic(&self, node_operator_id: PrincipalId) -> NodeOperatorRecord {
        let reg_value: RegistryValue = self
            .get(
                &make_node_operator_record_key(node_operator_id).into_bytes(),
                self.latest_version(),
            )
            .unwrap_or_else(|| {
                panic!(
                    "{LOG_PREFIX}node operator for {node_operator_id:} not found in the registry."
                );
            });

        NodeOperatorRecord::decode(reg_value.value.as_slice()).unwrap()
    }
}
