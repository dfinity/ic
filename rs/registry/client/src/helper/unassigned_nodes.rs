use ic_interfaces::registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::unassigned_nodes_config::v1::UnassignedNodesConfigRecord;
use ic_registry_common::values::deserialize_registry_value;
use ic_registry_keys::make_unassigned_nodes_config_record_key;
use ic_types::RegistryVersion;

pub trait UnassignedNodeRegistry {
    fn get_unassigned_nodes_config(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<UnassignedNodesConfigRecord>;
}

impl<T: RegistryClient + ?Sized> UnassignedNodeRegistry for T {
    fn get_unassigned_nodes_config(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<UnassignedNodesConfigRecord> {
        let bytes = self.get_value(&make_unassigned_nodes_config_record_key(), version);
        deserialize_registry_value::<UnassignedNodesConfigRecord>(bytes)
    }
}
