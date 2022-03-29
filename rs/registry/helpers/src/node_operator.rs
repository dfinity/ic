use crate::deserialize_registry_value;
use ic_interfaces::registry::{RegistryClient, RegistryClientResult};
pub use ic_protobuf::registry::node::v1::{ConnectionEndpoint, NodeRecord};
pub use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_registry_keys::make_node_operator_record_key;
pub use ic_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};

pub trait NodeOperatorRegistry {
    fn get_node_operator_record(
        &self,
        node_operator_id: PrincipalId,
        version: RegistryVersion,
    ) -> RegistryClientResult<NodeOperatorRecord>;
}

impl<T: RegistryClient + ?Sized> NodeOperatorRegistry for T {
    fn get_node_operator_record(
        &self,
        node_operator_id: PrincipalId,
        version: RegistryVersion,
    ) -> RegistryClientResult<NodeOperatorRecord> {
        let bytes = self.get_value(&make_node_operator_record_key(node_operator_id), version);
        deserialize_registry_value::<NodeOperatorRecord>(bytes)
    }
}
