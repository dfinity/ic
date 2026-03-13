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
        version: RegistryVersion,
        scope: &FirewallRulesScope,
    ) -> RegistryClientResult<FirewallRuleSet>;

    fn get_subnet_nodes_ip_addresses_of_types(
        &self,
        version: RegistryVersion,
        subnet_types: impl IntoIterator<Item = SubnetType>,
    ) -> RegistryClientResult<Vec<IpAddr>>;

    fn get_available_ip_addresses_for_node_ids(
        &self,
        version: RegistryVersion,
        node_ids: impl IntoIterator<Item = NodeId>,
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
        version: RegistryVersion,
        scope: &FirewallRulesScope,
    ) -> RegistryClientResult<FirewallRuleSet> {
        let bytes = self.get_value(&make_firewall_rules_record_key(scope), version);
        deserialize_registry_value::<FirewallRuleSet>(bytes)
    }

    /// Get the IP addresses of all system subnet nodes in the registry, for endpoints used for core protocol services (p2p, xnet, api)
    fn get_subnet_nodes_ip_addresses_of_types(
        &self,
        version: RegistryVersion,
        subnet_types: impl IntoIterator<Item = SubnetType>,
    ) -> RegistryClientResult<Vec<IpAddr>> {
        let subnet_ids = subnet_types
            .into_iter()
            .map(|subnet_id| {
                match self.get_subnet_ids_of_type(subnet_id, version) {
                    Ok(Some(ids)) => Ok(ids),
                    Ok(None) => Ok(vec![]),
                    Err(e) => Err(e), // Propagate any errors encountered while fetching subnet ids
                }
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        let node_ids = subnet_ids
            .into_iter()
            .map(|subnet_id| {
                match self.get_node_ids_on_subnet(subnet_id, version) {
                    Ok(Some(ids)) => Ok(ids),
                    Ok(None) => Ok(vec![]),
                    Err(e) => Err(e), // Propagate any errors encountered while fetching node ids
                }
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(Some(self.get_available_ip_addresses_for_node_ids(
            version, node_ids,
        )))
    }

    fn get_available_ip_addresses_for_node_ids(
        &self,
        version: RegistryVersion,
        node_ids: impl IntoIterator<Item = NodeId>,
    ) -> Vec<IpAddr> {
        let mut ip_addresses = HashSet::new();
        for node_id in node_ids {
            let Ok(Some(node_record)) = self.get_node_record(node_id, version) else {
                // Skip this node if there's an error fetching the node record or if it's not found
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::NodeRecord;
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::make_node_record_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_types::{NodeId, PrincipalId};
    use std::sync::Arc;

    // Helper function to create a registry client with the provided information.
    fn create_test_registry_client(
        registry_version: RegistryVersion,
        node_records: Vec<(NodeId, NodeRecord)>,
    ) -> Arc<dyn RegistryClient> {
        let data_provider = Arc::new(ProtoRegistryDataProvider::new());

        for (node_id, node_record) in node_records.into_iter() {
            data_provider
                .add(
                    &make_node_record_key(node_id),
                    registry_version,
                    Some(node_record),
                )
                .unwrap();
        }

        let registry = Arc::new(FakeRegistryClient::new(data_provider));
        registry.update_to_latest_version();
        registry as Arc<dyn RegistryClient>
    }
}
