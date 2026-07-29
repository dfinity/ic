use super::*;
use ic_logger::no_op_logger;
use ic_protobuf::registry::standard_engine_replica_version::v1::StandardEngineReplicaVersionRecord;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{make_standard_engine_replica_version_record_key, make_subnet_record_key};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::PrincipalId;
use lazy_static::lazy_static;

fn subnet_id(id: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(id))
}

lazy_static! {
    static ref REGISTRY_VERSION: RegistryVersion = RegistryVersion::new(42);
    static ref SUBNET_ID: SubnetId = subnet_id(777);
}

fn new_registry_helper(data_provider: ProtoRegistryDataProvider) -> RegistryHelper {
    let registry_client = Arc::new(FakeRegistryClient::new(Arc::new(data_provider)));
    registry_client.update_to_latest_version();

    RegistryHelper::new(
        NodeId::from(PrincipalId::new_node_test_id(1)),
        registry_client,
        no_op_logger(),
    )
}

#[test]
fn test_get_replica_version_when_specified_directly() {
    // Step 1: Prepare the world.

    let data_provider = ProtoRegistryDataProvider::new();

    data_provider
        .add(
            &make_subnet_record_key(*SUBNET_ID),
            *REGISTRY_VERSION,
            Some(SubnetRecord {
                replica_version_id: "some_version".to_string(),
                ..Default::default()
            }),
        )
        .unwrap();

    let registry = new_registry_helper(data_provider);

    // Step 2: Run the code under test.
    let result = registry.get_replica_version(*SUBNET_ID, *REGISTRY_VERSION);

    // Step 3: Verify result(s).
    assert_eq!(
        result.unwrap(),
        ReplicaVersion::try_from("some_version").unwrap(),
    );
}

#[test]
fn test_get_replica_version_standard_engine_replica_version() {
    for (deployment_progress, expected_replica_version_id) in [(1.0, "new"), (0.0, "old")] {
        // Step 1: Prepare the world.

        let data_provider = ProtoRegistryDataProvider::new();

        // CloudEngine that follows the standard replica version, i.e. has blank
        // replica_version_id.
        data_provider
            .add(
                &make_subnet_record_key(*SUBNET_ID),
                *REGISTRY_VERSION,
                Some(SubnetRecord {
                    replica_version_id: "".to_string(),
                    subnet_type: SubnetType::CloudEngine as i32,
                    ..Default::default()
                }),
            )
            .unwrap();

        // Standard engine replica version.
        data_provider
            .add(
                &make_standard_engine_replica_version_record_key(),
                *REGISTRY_VERSION,
                Some(StandardEngineReplicaVersionRecord {
                    new_replica_version_id: "new".to_string(),
                    old_replica_version_id: "old".to_string(),
                    deployment_progress,
                }),
            )
            .unwrap();

        let registry = new_registry_helper(data_provider);

        // Step 2: Run the code under test.
        let result = registry.get_replica_version(*SUBNET_ID, *REGISTRY_VERSION);

        // Step 3: Verify result(s).
        assert_eq!(
            result.unwrap(),
            ReplicaVersion::try_from(expected_replica_version_id).unwrap(),
        );
    }
}

#[test]
fn get_replica_version_is_an_error_when_the_subnet_is_missing() {
    // Step 1: Prepare the world.

    let data_provider = ProtoRegistryDataProvider::new();

    // This isn't really used by this test, but in order for this test to be
    // not completely trivial, we need SOME registry data.
    data_provider
        .add(
            &make_subnet_record_key(*SUBNET_ID),
            *REGISTRY_VERSION,
            Some(SubnetRecord {
                replica_version_id: "some_version".to_string(),
                ..Default::default()
            }),
        )
        .unwrap();

    let registry = new_registry_helper(data_provider);

    // Step 2: Run the code under test.
    let result = registry.get_replica_version(subnet_id(0x_DEAD_BEEF), *REGISTRY_VERSION);

    // Step 3: Verify result(s).
    match result {
        Err(OrchestratorError::SubnetMissingError(observed_subnet_id, observed_version)) => {
            assert_eq!(
                (observed_subnet_id, observed_version),
                (subnet_id(0x_DEAD_BEEF), *REGISTRY_VERSION),
            );
        }
        wrong => panic!("{wrong:?}"),
    }
}
