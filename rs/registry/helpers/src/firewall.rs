use crate::{
    deserialize_registry_value,
    node::NodeRegistry,
    subnet::{SubnetListRegistry, SubnetRegistry},
};
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::{
    firewall::v1::{FirewallConfig, FirewallRuleSet},
    subnet::v1::SubnetType,
};
use ic_registry_keys::{
    FirewallRulesScope, make_firewall_config_record_key, make_firewall_rules_record_key,
};
use ic_types::{NodeId, RegistryVersion};
use std::{collections::HashSet, net::IpAddr};

/// A trait that allows access to firewall rules and ancillary information.
pub trait FirewallRegistry {
    // TODO: Remove when IC-1026 is fully integrated
    fn get_firewall_config(&self, version: RegistryVersion)
    -> RegistryClientResult<FirewallConfig>;

    fn get_firewall_rules(
        &self,
        scope: &FirewallRulesScope,
        version: RegistryVersion,
    ) -> RegistryClientResult<FirewallRuleSet>;

    fn get_subnet_node_ids_of_types(
        &self,
        subnet_types: impl IntoIterator<Item = SubnetType>,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<NodeId>>;

    fn get_available_ip_addresses_for_node_ids(
        &self,
        node_ids: impl IntoIterator<Item = NodeId>,
        version: RegistryVersion,
    ) -> Vec<IpAddr>;
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
        scope: &FirewallRulesScope,
        version: RegistryVersion,
    ) -> RegistryClientResult<FirewallRuleSet> {
        let bytes = self.get_value(&make_firewall_rules_record_key(scope), version);
        deserialize_registry_value::<FirewallRuleSet>(bytes)
    }

    /// Get the IP addresses of nodes in the registry for all subnets of the given types, for
    /// endpoints used for core protocol services (p2p, xnet, api).
    fn get_subnet_node_ids_of_types(
        &self,
        subnet_types: impl IntoIterator<Item = SubnetType>,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<NodeId>> {
        let subnet_ids = subnet_types
            .into_iter()
            .map(|subnet_id| {
                self.get_subnet_ids_of_type(subnet_id, version)
                    .map(Option::unwrap_or_default)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let node_ids = subnet_ids
            .into_iter()
            .map(|subnet_id| {
                self.get_node_ids_on_subnet(subnet_id, version)
                    .map(Option::unwrap_or_default)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(Some(node_ids))
    }

    /// Get the IP addresses of the given nodes in the registry, for endpoints used for core
    /// protocol services (p2p, xnet, api). If a node record is not found or there's an error
    /// fetching it, that node will be skipped.
    fn get_available_ip_addresses_for_node_ids(
        &self,
        node_ids: impl IntoIterator<Item = NodeId>,
        version: RegistryVersion,
    ) -> Vec<IpAddr> {
        let mut ip_addresses = HashSet::new();
        for node_id in node_ids {
            let Ok(Some(node_record)) = self.get_node_record(node_id, version) else {
                continue;
            };

            if let Some(endpoint) = node_record.xnet
                && let Ok(ip_addr) = endpoint.ip_addr.parse::<IpAddr>()
            {
                ip_addresses.insert(ip_addr);
            }
            if let Some(endpoint) = node_record.http
                && let Ok(ip_addr) = endpoint.ip_addr.parse::<IpAddr>()
            {
                ip_addresses.insert(ip_addr);
            }
        }

        Vec::from_iter(ip_addresses)
    }
}
