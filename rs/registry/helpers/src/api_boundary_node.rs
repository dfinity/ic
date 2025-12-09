use crate::deserialize_registry_value;
use ic_base_types::{NodeId, RegistryVersion};
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
use ic_registry_keys::{
    API_BOUNDARY_NODE_RECORD_KEY_PREFIX, get_api_boundary_node_record_node_id,
    make_api_boundary_node_record_key,
};
use ic_types::registry::RegistryClientError;
use std::collections::HashSet;

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

    fn get_system_api_boundary_node_ids(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError>;

    fn get_app_api_boundary_node_ids(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError>;

    fn is_system_api_boundary_node(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> Result<bool, RegistryClientError>;
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

    fn get_system_api_boundary_node_ids(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError> {
        let mut all_ids = self.get_api_boundary_node_ids(version)?;
        all_ids.sort();
        let n = all_ids.len();
        let split_point = n.div_ceil(2);
        all_ids.truncate(split_point);
        Ok(all_ids)
    }

    fn get_app_api_boundary_node_ids(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<NodeId>, RegistryClientError> {
        let all_ids = self.get_api_boundary_node_ids(version)?;
        let system_ids: HashSet<NodeId> =
            HashSet::from_iter(self.get_system_api_boundary_node_ids(version)?);

        let app_ids: Vec<NodeId> = all_ids
            .into_iter()
            .filter(|id| !system_ids.contains(id))
            .collect();

        Ok(app_ids)
    }

    fn is_system_api_boundary_node(
        &self,
        node_id: NodeId,
        version: RegistryVersion,
    ) -> Result<bool, RegistryClientError> {
        let system_api_bn_ids = self.get_system_api_boundary_node_ids(version)?;
        Ok(system_api_bn_ids.contains(&node_id))
    }
}

#[cfg(test)]
#[path = "api_boundary_node_tests.rs"]
mod tests;
