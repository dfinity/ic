use super::*;
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

    let registry = create_test_registry_client(version, node_records);
    let ip_addrs = registry
        .get_all_nodes_ip_addresses(version)
        .unwrap()
        .unwrap();

    for ip_addr in &test_ip_addrs {
        assert!(ip_addrs.contains(ip_addr));
    }
}
