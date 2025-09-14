use crate::deserialize_registry_value;
use ic_base_types::RegistryVersion;
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::replica_version::v1::BlessedReplicaVersions;
use ic_registry_keys::make_blessed_replica_versions_key;

pub trait BlessedReplicaVersionRegistry {
    fn get_blessed_replica_versions(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<BlessedReplicaVersions>;
}

impl<T: RegistryClient + ?Sized> BlessedReplicaVersionRegistry for T {
    fn get_blessed_replica_versions(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<BlessedReplicaVersions> {
        deserialize_registry_value(self.get_value(&make_blessed_replica_versions_key(), version))
    }
}
