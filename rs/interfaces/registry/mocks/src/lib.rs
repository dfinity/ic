use ic_base_types::RegistryVersion;
use ic_interfaces_registry::{RegistryClient, RegistryClientResult, RegistryClientVersionedResult};
use ic_types::{Time, registry::RegistryClientError};
use mockall::*;

mock! {
    pub RegistryClient {}

    impl RegistryClient for RegistryClient {
        fn get_value(&self, key: &str, version: RegistryVersion) -> RegistryClientResult<Vec<u8>>;
        fn get_versioned_value(
            &self,
            key: &str,
            version: RegistryVersion,
        ) -> RegistryClientVersionedResult<Vec<u8>>;

        fn get_key_family(&self,
            key_prefix: &str,
            version: RegistryVersion
        ) -> Result<Vec<String>, RegistryClientError>;

        fn get_latest_version(&self) -> RegistryVersion;

        fn get_version_timestamp(&self, registry_version: RegistryVersion) -> Option<Time>;
    }
}
