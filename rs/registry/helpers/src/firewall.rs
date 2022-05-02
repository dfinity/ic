use crate::deserialize_registry_value;
use ic_interfaces::registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::firewall::v1::FirewallConfig;
use ic_protobuf::registry::firewall::v1::FirewallRuleSet;
use ic_registry_keys::make_firewall_config_record_key;
use ic_registry_keys::make_firewall_rules_record_key;
use ic_types::RegistryVersion;

/// A trait that allows access to `FirewallConfig`.  The expectation for the
/// forseeable future is that the `FirewallConfig` will remain small enough so
/// that we can simply return the entire struct here.
pub trait FirewallRegistry {
    // TODO: Remove when IC-1026 is fully integrated
    fn get_firewall_config(&self, version: RegistryVersion)
        -> RegistryClientResult<FirewallConfig>;

    fn get_firewall_rules(
        &self,
        version: RegistryVersion,
        id: &str,
    ) -> RegistryClientResult<FirewallRuleSet>;
}

impl<T: RegistryClient + ?Sized> FirewallRegistry for T {
    // TODO: Remove when IC-1026 is fully integrated
    fn get_firewall_config(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<FirewallConfig> {
        let bytes = self.get_value(&make_firewall_config_record_key(), version);
        deserialize_registry_value::<FirewallConfig>(bytes)
    }

    fn get_firewall_rules(
        &self,
        version: RegistryVersion,
        id: &str,
    ) -> RegistryClientResult<FirewallRuleSet> {
        let bytes = self.get_value(&make_firewall_rules_record_key(id), version);
        deserialize_registry_value::<FirewallRuleSet>(bytes)
    }
}
