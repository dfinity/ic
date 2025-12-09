use super::*;
use ic_base_types::PrincipalId;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use std::sync::Arc;

fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_user_test_id(id))
}

fn setup_test_client(
    node_ids: Vec<NodeId>,
    version: RegistryVersion,
) -> Arc<dyn RegistryClient> {
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    for node_id in node_ids {
        let record = ApiBoundaryNodeRecord::default();
        data_provider
            .add(
                &make_api_boundary_node_record_key(node_id),
                version,
                Some(record),
            )
            .unwrap();
    }

    let registry_client = Arc::new(FakeRegistryClient::new(data_provider));
    registry_client.update_to_latest_version();
    registry_client
}

#[test]
fn test_split_even_nodes() {
    let version = RegistryVersion::from(1);
    let registry = setup_test_client(
        vec![node_id(1), node_id(2), node_id(3), node_id(4)],
        version,
    );

    let system_ids = registry.get_system_api_boundary_node_ids(version).unwrap();
    let mut app_ids = registry.get_app_api_boundary_node_ids(version).unwrap();
    app_ids.sort(); // Sort for deterministic comparison

    assert_eq!(system_ids, vec![node_id(1), node_id(2)]);
    assert_eq!(app_ids, vec![node_id(3), node_id(4)]);
}

#[test]
fn test_split_odd_nodes() {
    let version = RegistryVersion::from(1);
    let registry = setup_test_client(
        vec![
            node_id(10),
            node_id(20),
            node_id(30),
            node_id(40),
            node_id(50),
        ],
        version,
    );

    let system_ids = registry.get_system_api_boundary_node_ids(version).unwrap();
    let mut app_ids = registry.get_app_api_boundary_node_ids(version).unwrap();
    app_ids.sort();

    assert_eq!(system_ids, vec![node_id(10), node_id(20), node_id(30)]);
    assert_eq!(app_ids, vec![node_id(40), node_id(50)]);
}

#[test]
fn test_split_single_node() {
    let version = RegistryVersion::from(1);
    let registry = setup_test_client(vec![node_id(100)], version);

    let system_ids = registry.get_system_api_boundary_node_ids(version).unwrap();
    let app_ids = registry.get_app_api_boundary_node_ids(version).unwrap();

    assert_eq!(system_ids, vec![node_id(100)]);
    assert!(app_ids.is_empty());
}

#[test]
fn test_is_system_api_boundary_node() {
    let version = RegistryVersion::from(1);
    let registry = setup_test_client(
        vec![node_id(1), node_id(2), node_id(3), node_id(4)],
        version,
    );

    assert!(
        registry
            .is_system_api_boundary_node(node_id(1), version)
            .unwrap()
    );
    assert!(
        registry
            .is_system_api_boundary_node(node_id(2), version)
            .unwrap()
    );
    assert!(
        !registry
            .is_system_api_boundary_node(node_id(3), version)
            .unwrap()
    );
    assert!(
        !registry
            .is_system_api_boundary_node(node_id(4), version)
            .unwrap()
    );
}
