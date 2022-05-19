use crate::deserialize_registry_value;
use crate::node::NodeRecord;
use ic_interfaces::registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::firewall::v1::FirewallConfig;
use ic_protobuf::registry::firewall::v1::FirewallRuleSet;
use ic_protobuf::registry::node::v1::ConnectionEndpoint;
use ic_registry_keys::get_node_record_node_id;
use ic_registry_keys::make_firewall_config_record_key;
use ic_registry_keys::make_firewall_rules_record_key;
use ic_registry_keys::make_node_record_key;
use ic_registry_keys::FirewallRulesScope;
use ic_registry_keys::NODE_RECORD_KEY_PREFIX;
use ic_types::{NodeId, RegistryVersion};
use std::collections::HashSet;
use std::net::IpAddr;

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
                        endpoints.extend::<Vec<ConnectionEndpoint>>(
                            node_record
                                .p2p_flow_endpoints
                                .iter()
                                .filter_map(|flow_endpoint| flow_endpoint.endpoint.clone())
                                .collect(),
                        );
                        endpoints.extend::<Vec<ConnectionEndpoint>>(node_record.xnet_api);
                        endpoints.extend::<Vec<ConnectionEndpoint>>(node_record.public_api);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_protobuf::registry::node::v1::FlowEndpoint;
    use ic_registry_client_fake::FakeRegistryClient;
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
    fn can_get_node_ips() {
        let test_ip_addrs: Vec<IpAddr> = vec![
            "1::".parse().unwrap(),
            "2::".parse().unwrap(),
            "3::".parse().unwrap(),
            "4::".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "192.168.0.1".parse().unwrap(),
        ];

        let node_records = test_ip_addrs
            .iter()
            .enumerate()
            .map(|(id, ip)| {
                (
                    NodeId::from(PrincipalId::new_node_test_id(id as u64)),
                    NodeRecord {
                        xnet: None,
                        http: None,
                        p2p_flow_endpoints: vec![FlowEndpoint {
                            flow_tag: 1,
                            endpoint: Some(ConnectionEndpoint {
                                ip_addr: ip.to_string(),
                                port: 4000,
                                protocol: 3,
                            }),
                        }],
                        prometheus_metrics_http: None,
                        public_api: vec![ConnectionEndpoint {
                            ip_addr: ip.to_string(),
                            port: 8080,
                            protocol: 2,
                        }],
                        private_api: vec![],
                        prometheus_metrics: vec![],
                        xnet_api: vec![ConnectionEndpoint {
                            ip_addr: ip.to_string(),
                            port: 2457,
                            protocol: 2,
                        }],
                        node_operator_id: vec![],
                    },
                )
            })
            .collect();

        let version = RegistryVersion::from(2);

        let registry = create_test_registry_client(version, node_records);
        let ip_addrs = registry
            .get_all_nodes_ip_addresses(version)
            .unwrap()
            .unwrap();

        for ip_addr in &test_ip_addrs {
            assert!(ip_addrs.contains(ip_addr));
        }
    }
}
