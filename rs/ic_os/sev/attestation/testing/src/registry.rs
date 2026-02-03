use ic_interfaces_registry_mocks::MockRegistryClient;
use ic_protobuf::registry::replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord};
use ic_registry_keys::{make_blessed_replica_versions_key, make_replica_version_key};
use ic_types::RegistryVersion;
use mockall::predicate::eq;
use prost::Message;

/// Create a mock registry client with the specified blessed replica versions and their
/// corresponding version records.
pub fn setup_mock_registry_client_with_blessed_versions(
    registry_version: RegistryVersion,
    blessed_version_ids: &[&str],
    replica_versions_and_records: &[(&str, ReplicaVersionRecord)],
) -> MockRegistryClient {
    let mut mock_client = MockRegistryClient::new();

    mock_client
        .expect_get_latest_version()
        .return_const(registry_version);

    let blessed_versions = BlessedReplicaVersions {
        blessed_version_ids: blessed_version_ids.iter().map(|x| x.to_string()).collect(),
    };

    mock_client
        .expect_get_value()
        .with(
            eq(make_blessed_replica_versions_key()),
            eq(registry_version),
        )
        .returning(move |_, _| Ok(Some(blessed_versions.encode_to_vec())));

    for (version_key, record) in replica_versions_and_records {
        let encoded_record = record.encode_to_vec();
        mock_client
            .expect_get_value()
            .with(
                eq(make_replica_version_key(version_key)),
                eq(registry_version),
            )
            .returning(move |_, _| Ok(Some(encoded_record.clone())));
    }

    mock_client
}
