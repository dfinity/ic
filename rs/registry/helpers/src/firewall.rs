use crate::{
    deserialize_registry_value,
    node::NodeRecord,
    subnet::{SubnetListRegistry, SubnetRegistry},
};
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::{
    firewall::v1::{FirewallConfig, FirewallRuleSet},
    node::v1::ConnectionEndpoint,
};
use ic_registry_keys::{
    FirewallRulesScope, NODE_RECORD_KEY_PREFIX, get_node_record_node_id,
    make_firewall_config_record_key, make_firewall_rules_record_key, make_node_record_key,
};
use ic_types::{NodeId, RegistryVersion, SubnetId};
use std::{collections::HashSet, net::IpAddr};

/// A trait that allows access to firewall rules and ancillary information.
pub trait FirewallRegistry {
    // TODO: Remove when IC-1026 is fully integrated
    fn get_firewall_config(&self, version: RegistryVersion)
    -> RegistryClientResult<FirewallConfig>;

    fn get_firewall_rules(
        &self,
        version: RegistryVersion,
        scope: &FirewallRulesScope,
    ) -> RegistryClientResult<FirewallRuleSet>;

    fn get_all_nodes_ip_addresses(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<IpAddr>>;

    fn get_system_subnet_nodes_ip_addresses(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<IpAddr>>;

    fn get_app_subnet_nodes_ip_addresses(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<IpAddr>>;

    fn get_ip_addresses_for_node_ids(
        &self,
        version: RegistryVersion,
        node_ids: &[NodeId],
    ) -> RegistryClientResult<Vec<IpAddr>>;
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
        scope: &FirewallRulesScope,
    ) -> RegistryClientResult<FirewallRuleSet> {
        let bytes = self.get_value(&make_firewall_rules_record_key(scope), version);
        deserialize_registry_value::<FirewallRuleSet>(bytes)
    }

    /// Get all the IP addresses of all nodes in the registry, for endpoints used for core protocol services (p2p, xnet, api)
    fn get_all_nodes_ip_addresses(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<IpAddr>> {
        let node_record_keys = self.get_key_family(NODE_RECORD_KEY_PREFIX, version)?;

        // Go over all node IDs, get their corresponding node records, extract all p2p, xnet, api endpoints,
        // put into a set (to remove duplicates), and then collect into a list.
        let result: Vec<IpAddr> = node_record_keys
            .iter()
            .filter_map(|s| get_node_record_node_id(s.as_str()))
            .map(NodeId::from)
            .filter_map(|node_id| {
                match deserialize_registry_value::<NodeRecord>(
                    self.get_value(&make_node_record_key(node_id), version),
                ) {
                    Ok(Some(node_record)) => {
                        let mut endpoints: Vec<ConnectionEndpoint> = Vec::new();
                        if let Some(xnet_record) = node_record.xnet {
                            endpoints.push(xnet_record)
                        };
                        if let Some(http_record) = node_record.http {
                            endpoints.push(http_record)
                        };
                        Some(endpoints)
                    }
                    _ => None,
                }
            })
            .flatten()
            .filter_map(|connection_endpoint| connection_endpoint.ip_addr.parse::<IpAddr>().ok())
            .collect::<HashSet<IpAddr>>()
            .into_iter()
            .collect();
        Ok(Some(result))
    }

    /// Get the IP addresses of all system subnet nodes in the registry, for endpoints used for core protocol services (p2p, xnet, api)
    fn get_system_subnet_nodes_ip_addresses(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<IpAddr>> {
        let system_subnet_node_ids: Vec<NodeId> = self
            .get_system_subnet_ids(version)?
            .unwrap_or_default()
            .into_iter()
            .map(
                |subnet_id| match self.get_node_ids_on_subnet(subnet_id, version) {
                    Ok(Some(node_ids)) => Ok(node_ids),
                    Ok(None) => Ok(vec![]),
                    Err(e) => Err(e),
                },
            )
            .collect::<Result<Vec<Vec<NodeId>>, _>>()?
            .into_iter()
            .flatten()
            .collect();

        self.get_ip_addresses_for_node_ids(version, &system_subnet_node_ids)
    }

    /// Get the IP addresses of all app subnet nodes in the registry, for endpoints used for core protocol services (p2p, xnet, api)
    fn get_app_subnet_nodes_ip_addresses(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<IpAddr>> {
        let all_subnet_ids = self.get_subnet_ids(version)?.unwrap_or_default();
        let system_subnet_ids = self.get_system_subnet_ids(version)?.unwrap_or_default();

        let app_subnet_ids: Vec<SubnetId> = all_subnet_ids
            .into_iter()
            .filter(|id| !system_subnet_ids.contains(id))
            .collect();

        let app_subnet_node_ids: Vec<NodeId> = app_subnet_ids
            .into_iter()
            .map(
                |subnet_id| match self.get_node_ids_on_subnet(subnet_id, version) {
                    Ok(Some(node_ids)) => Ok(node_ids),
                    Ok(None) => Ok(vec![]),
                    Err(e) => Err(e),
                },
            )
            .collect::<Result<Vec<Vec<NodeId>>, _>>()?
            .into_iter()
            .flatten()
            .collect();

        self.get_ip_addresses_for_node_ids(version, &app_subnet_node_ids)
    }

    /// Get the IP addresses of the specified nodes
    fn get_ip_addresses_for_node_ids(
        &self,
        version: RegistryVersion,
        node_ids: &[NodeId],
    ) -> RegistryClientResult<Vec<IpAddr>> {
        let mut node_endpoints: HashSet<IpAddr> = HashSet::new();

        for node_id in node_ids {
            if let Some(node_record) = deserialize_registry_value::<NodeRecord>(
                self.get_value(&make_node_record_key(*node_id), version),
            )? {
                if let Some(ip_addr) = node_record
                    .xnet
                    .and_then(|endpoint| endpoint.ip_addr.parse::<IpAddr>().ok())
                {
                    node_endpoints.insert(ip_addr);
                }
                if let Some(ip_addr) = node_record
                    .http
                    .and_then(|endpoint| endpoint.ip_addr.parse::<IpAddr>().ok())
                {
                    node_endpoints.insert(ip_addr);
                }
            }
        }

        Ok(Some(Vec::from_iter(node_endpoints)))
    }
}

#[cfg(test)]
#[path = "firewall_tests.rs"]
mod tests;
