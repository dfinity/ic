use ic_interfaces::registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::firewall::v1::FirewallConfig;
use ic_registry_common::values::deserialize_registry_value;
use ic_registry_keys::make_firewall_config_record_key;
use ic_types::RegistryVersion;

/// A trait that allows access to `FirewallConfig`.  The expectation for the
/// forseeable future is that the `FirewallConfig` will remain small enough so
/// that we can simply return the entire struct here.
pub trait FirewallRegistry {
    fn get_firewall_config(&self, version: RegistryVersion)
        -> RegistryClientResult<FirewallConfig>;
}

impl<T: RegistryClient + ?Sized> FirewallRegistry for T {
    fn get_firewall_config(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<FirewallConfig> {
        let bytes = self.get_value(&make_firewall_config_record_key(), version);
        deserialize_registry_value::<FirewallConfig>(bytes)
    }
}
