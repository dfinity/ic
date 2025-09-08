use crate::deserialize_registry_value;
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::hostos_version::v1::HostosVersionRecord;
use ic_registry_keys::{HOSTOS_VERSION_KEY_PREFIX, make_hostos_version_key};
pub use ic_types::hostos_version::HostosVersion;
pub use ic_types::{NodeId, RegistryVersion, SubnetId};

pub trait HostosRegistry {
    fn get_hostos_versions(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<HostosVersionRecord>>;

    fn get_hostos_version_record(
        &self,
        hostos_version_id: &HostosVersion,
        version: RegistryVersion,
    ) -> RegistryClientResult<HostosVersionRecord>;
}

impl<T: RegistryClient + ?Sized> HostosRegistry for T {
    fn get_hostos_versions(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<HostosVersionRecord>> {
        let keys = self.get_key_family(HOSTOS_VERSION_KEY_PREFIX, version)?;

        let mut records = Vec::new();
        for key in keys {
            let bytes = self.get_value(&key, version);
            let hostos_version_proto =
                deserialize_registry_value::<HostosVersionRecord>(bytes)?.unwrap_or_default();
            records.push(hostos_version_proto)
        }

        Ok(Some(records))
    }

    fn get_hostos_version_record(
        &self,
        hostos_version_id: &HostosVersion,
        version: RegistryVersion,
    ) -> RegistryClientResult<HostosVersionRecord> {
        let bytes = self.get_value(&make_hostos_version_key(hostos_version_id), version);
        deserialize_registry_value::<HostosVersionRecord>(bytes)
    }
}
