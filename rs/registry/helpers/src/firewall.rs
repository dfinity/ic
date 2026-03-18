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
        subnet_types: Vec<SubnetType>,
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
        subnet_types: Vec<SubnetType>,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<NodeId>> {
        let Some(all_subnet_ids) = self.get_subnet_ids(version)? else {
            return Ok(None);
        };

        let node_ids = all_subnet_ids
            .into_iter()
            .filter(|subnet_id| {
                subnet_types.iter().any(|target_type| {
                    self.get_subnet_type(*subnet_id, version) == Ok(Some(*target_type))
                })
            })
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

#[cfg(test)]
mod tests {
    use super::*;
    use ic_protobuf::registry::node::v1::{ConnectionEndpoint, NodeRecord};
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::make_node_record_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use ic_types::PrincipalId;
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

    #[test]
    fn test_get_available_ip_addresses_for_node_ids() {
        let test_ip_addrs: Vec<IpAddr> = vec![
            "1::".parse().unwrap(),
            "2::".parse().unwrap(),
            "3::".parse().unwrap(),
            "4::".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "192.168.0.1".parse().unwrap(),
        ];
        let test_records: Vec<(NodeId, NodeRecord)> = test_ip_addrs
            .iter()
            .cloned()
            .enumerate()
            .map(|(id, ip)| {
                (
                    NodeId::from(PrincipalId::new_node_test_id(id as u64)),
                    NodeRecord {
                        http: Some(ConnectionEndpoint {
                            ip_addr: ip.to_string(),
                            port: 8080,
                        }),
                        xnet: Some(ConnectionEndpoint {
                            ip_addr: ip.to_string(),
                            port: 2457,
                        }),
                        ..Default::default()
                    },
                )
            })
            .collect();

        let version = RegistryVersion::from(2);

        let registry = create_test_registry_client(version, test_records.clone());
        let ip_addrs = registry.get_available_ip_addresses_for_node_ids(
            test_records
                .iter()
                .map(|(node_id, _)| *node_id)
                .chain(
                    // Add some node IDs that do not exist in the registry to ensure they are
                    // skipped without error.
                    [
                        NodeId::from(PrincipalId::new_node_test_id(999)),
                        NodeId::from(PrincipalId::new_node_test_id(1000)),
                    ],
                )
                .collect::<Vec<_>>(),
            version,
        );

        // Compare as sets since the order of IP addresses is not guaranteed.
        assert_eq!(
            HashSet::<IpAddr>::from_iter(ip_addrs),
            HashSet::<IpAddr>::from_iter(test_ip_addrs)
        );
    }
}
