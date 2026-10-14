use crate::deserialize_registry_value;
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
pub use ic_protobuf::registry::node::v1::{ConnectionEndpoint, NodeRecord};
pub use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::{NODE_OPERATOR_RECORD_KEY_PREFIX, make_node_operator_record_key};
pub use ic_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};

pub trait NodeOperatorRegistry {
    fn get_node_operators(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<NodeOperatorRecord>>;

    fn get_node_operator_record(
        &self,
        node_operator_id: PrincipalId,
        version: RegistryVersion,
    ) -> RegistryClientResult<NodeOperatorRecord>;
}

impl<T: RegistryClient + ?Sized> NodeOperatorRegistry for T {
    fn get_node_operators(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<NodeOperatorRecord>> {
        let keys = self.get_key_family(NODE_OPERATOR_RECORD_KEY_PREFIX, version)?;

        let mut records = Vec::new();
        for key in keys {
            let bytes = self.get_value(&key, version);
            let node_operator_proto =
                deserialize_registry_value::<NodeOperatorRecord>(bytes)?.unwrap_or_default();
            records.push(node_operator_proto)
        }

        Ok(Some(records))
    }

    fn get_node_operator_record(
        &self,
        node_operator_id: PrincipalId,
        version: RegistryVersion,
    ) -> RegistryClientResult<NodeOperatorRecord> {
        let bytes = self.get_value(&make_node_operator_record_key(node_operator_id), version);
        deserialize_registry_value::<NodeOperatorRecord>(bytes)
    }
}
