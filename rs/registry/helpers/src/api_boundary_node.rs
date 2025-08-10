use ic_base_types::{NodeId, RegistryVersion};
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
use ic_registry_keys::{
    get_api_boundary_node_record_node_id, make_api_boundary_node_record_key,
    API_BOUNDARY_NODE_RECORD_KEY_PREFIX,
};
use ic_types::registry::RegistryClientError;

use crate::deserialize_registry_value;

pub trait ApiBoundaryNodeRegistry {
    fn get_api_boundary_node_ids(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError>;

    fn get_api_boundary_node_record(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<ApiBoundaryNodeRecord>;
}

impl<T: RegistryClient + ?Sized> ApiBoundaryNodeRegistry for T {
    fn get_api_boundary_node_ids(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError> {
        let api_boundary_node_record_keys =
            self.get_key_family(API_BOUNDARY_NODE_RECORD_KEY_PREFIX, version)?;
        let res = api_boundary_node_record_keys
            .iter()
            .filter_map(|s| get_api_boundary_node_record_node_id(s))
            .map(NodeId::from)
            .collect();
        Ok(res)
    }

    fn get_api_boundary_node_record(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> RegistryClientResult<ApiBoundaryNodeRecord> {
        let bytes = self.get_value(&make_api_boundary_node_record_key(node_id), version);
        deserialize_registry_value::<ApiBoundaryNodeRecord>(bytes)
    }
}
