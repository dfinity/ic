use super::*;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::PrincipalId;
use std::sync::Arc;

fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

fn subnet_id(id: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(id))
}

// Helper function to create a registry client with the provided information.
fn create_test_registry_client(
    registry_version: RegistryVersion,
    subnet_records: Vec<(SubnetId, SubnetRecord)>,
    replica_version: Option<ReplicaVersion>,
) -> Arc<FakeRegistryClient> {
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());

    for (subnet_id, subnet_record) in subnet_records.into_iter() {
        data_provider
            .add(
                &make_subnet_record_key(subnet_id),
                registry_version,
                Some(subnet_record),
            )
            .unwrap();
    }

    if let Some(replica_version) = replica_version {
        let replica_version_record = ReplicaVersionRecord::default();
        data_provider
            .add(
                &make_replica_version_key(String::from(&replica_version)),
                registry_version,
                Some(replica_version_record),
            )
            .unwrap();
    }

    let registry = Arc::new(FakeRegistryClient::new(data_provider));
    registry.update_to_latest_version();
    registry
}

#[test]
fn can_get_node_ids_from_subnet() {
    let subnet_id = subnet_id(4);
    let version = RegistryVersion::from(2);
    let subnet_record = SubnetRecord {
        membership: vec![
            node_id(32u64).get().into_vec(),
            node_id(33u64).get().into_vec(),
        ],
        ..Default::default()
    };

    let registry = create_test_registry_client(version, vec![(subnet_id, subnet_record)], None);

    let node_ids = registry.get_node_ids_on_subnet(subnet_id, version).unwrap();

    assert_eq!(node_ids, Some(vec![node_id(32), node_id(33)]));
}

#[test]
fn can_get_replica_version_from_subnet() {
    let subnet_id = subnet_id(4);
    let version = RegistryVersion::from(2);

    let replica_version = ReplicaVersion::try_from("some_version").unwrap();
    let replica_version_record = ReplicaVersionRecord::default();

    let subnet_record = SubnetRecord {
        replica_version_id: String::from(&replica_version),
        ..Default::default()
    };

    let registry = create_test_registry_client(
        version,
        vec![(subnet_id, subnet_record)],
        Some(replica_version.clone()),
    );

    let result = registry.get_replica_version(subnet_id, version).unwrap();
    assert_eq!(result, Some(replica_version));

    let result = registry
        .get_replica_version_record(subnet_id, version)
        .unwrap();
    assert_eq!(result, Some(replica_version_record))
}

#[test]
fn can_get_is_halted_from_subnet() {
    let subnet_id = subnet_id(4);
    let version = RegistryVersion::from(2);

    for is_halted in [false, true] {
        let subnet_record = SubnetRecord {
            is_halted,
            ..Default::default()
        };

        let registry =
            create_test_registry_client(version, vec![(subnet_id, subnet_record)], None);

        assert_eq!(
            registry.get_is_halted(subnet_id, version),
            Ok(Some(is_halted))
        );
    }
}

#[test]
fn can_get_halt_at_cup_height_from_subnet() {
    let subnet_id = subnet_id(4);
    let version = RegistryVersion::from(2);

    for halt_at_cup_height in [false, true] {
        let subnet_record = SubnetRecord {
            halt_at_cup_height,
            ..Default::default()
        };

        let registry =
            create_test_registry_client(version, vec![(subnet_id, subnet_record)], None);

        assert_eq!(
            registry.get_halt_at_cup_height(subnet_id, version),
            Ok(Some(halt_at_cup_height))
        );
    }
}

#[test]
fn can_get_max_block_size_from_subnet_record() {
    let subnet_id = subnet_id(4);
    let version = RegistryVersion::from(2);
    let max_block_payload_size_bytes = 4 * 1024 * 1024; // 4MiB
    let replica_version = ReplicaVersion::try_from("some_version").unwrap();

    let subnet_record = SubnetRecord {
        max_block_payload_size: max_block_payload_size_bytes,
        replica_version_id: String::from(&replica_version),
        ..Default::default()
    };

    let registry = create_test_registry_client(
        version,
        vec![(subnet_id, subnet_record)],
        Some(replica_version.clone()),
    );

    let result = registry.get_replica_version(subnet_id, version).unwrap();
    assert_eq!(result, Some(replica_version));

    let result = registry
        .get_max_block_payload_size_bytes(subnet_id, version)
        .unwrap();
    assert_eq!(result, Some(max_block_payload_size_bytes))
}
