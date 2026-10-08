use crate::deserialize_registry_value;
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::{
    replica_version::v1::ReplicaVersionRecord,
    standard_engine_replica_version::v1::StandardEngineReplicaVersionRecord,
};
use ic_registry_keys::{
    REPLICA_VERSION_KEY_PREFIX, make_replica_version_key,
    make_standard_engine_replica_version_record_key,
};
use ic_types::registry::RegistryClientError;
pub use ic_types::replica_version::ReplicaVersion;
pub use ic_types::{NodeId, RegistryVersion, SubnetId};

pub trait ReplicaVersionRegistry {
    fn get_all_replica_version_records(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<(String, ReplicaVersionRecord)>>;

    fn get_replica_version_record(
        &self,
        replica_version_id: &ReplicaVersion,
        version: RegistryVersion,
    ) -> RegistryClientResult<ReplicaVersionRecord>;

    fn get_standard_engine_replica_version_record(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<StandardEngineReplicaVersionRecord>;

    /// Returns all guest launch measurements from all replica versions.
    ///
    /// This method fetches all replica version records from the registry at
    /// the given version, and collects all guest launch measurements from
    /// those records.
    fn get_guest_launch_measurements(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<Vec<u8>>, String>;
}

impl<T: RegistryClient + ?Sized> ReplicaVersionRegistry for T {
    fn get_all_replica_version_records(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<Vec<(String, ReplicaVersionRecord)>> {
        // Note this `get_key_family` impl does not strip the prefix from keys. The impl in the registry canister, does.
        let keys = self.get_key_family(REPLICA_VERSION_KEY_PREFIX, version)?;

        let mut records = Vec::new();
        for key in keys {
            let bytes = self.get_value(&key, version);
            let replica_version_proto =
                deserialize_registry_value::<ReplicaVersionRecord>(bytes)?.unwrap_or_default();
            let id = key
                .strip_prefix(REPLICA_VERSION_KEY_PREFIX)
                .ok_or_else(|| RegistryClientError::DecodeError {
                    error: format!("Replica Version Record key {key} does not start with prefix {REPLICA_VERSION_KEY_PREFIX}"),
                })?
                .to_string();
            records.push((id, replica_version_proto))
        }

        Ok(Some(records))
    }

    fn get_replica_version_record(
        &self,
        replica_version_id: &ReplicaVersion,
        version: RegistryVersion,
    ) -> RegistryClientResult<ReplicaVersionRecord> {
        let bytes = self.get_value(&make_replica_version_key(replica_version_id), version);
        deserialize_registry_value::<ReplicaVersionRecord>(bytes)
    }

    fn get_standard_engine_replica_version_record(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<StandardEngineReplicaVersionRecord> {
        let bytes = self.get_value(&make_standard_engine_replica_version_record_key(), version);
        deserialize_registry_value::<StandardEngineReplicaVersionRecord>(bytes)
    }

    fn get_guest_launch_measurements(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<Vec<u8>>, String> {
        let replica_versions = self
            .get_all_replica_version_records(version)
            .map_err(|err| format!("Failed to get replica versions: {err}"))?
            .ok_or_else(|| "Elected replica versions not found in registry".to_string())?;

        let measurements = replica_versions
            .into_iter()
            .flat_map(|(_, record)| {
                record
                    .guest_launch_measurements
                    .unwrap_or_default()
                    .guest_launch_measurements
            })
            .map(|measurement| measurement.measurement)
            .collect();

        Ok(measurements)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_protobuf::registry::replica_version::v1::{
        GuestLaunchMeasurement, GuestLaunchMeasurements, ReplicaVersionRecord,
    };
    use ic_registry_client_fake::FakeRegistryClient;
    use ic_registry_keys::make_replica_version_key;
    use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
    use std::sync::Arc;

    fn create_replica_record(
        replica_version_id: &str,
        package_hash: &str,
        measurements: &[impl AsRef<[u8]>],
    ) -> ReplicaVersionRecord {
        ReplicaVersionRecord {
            replica_version_id: Some(replica_version_id.to_string()),
            release_package_sha256_hex: package_hash.to_string(),
            release_package_urls: vec![],
            guest_launch_measurements: Some(GuestLaunchMeasurements {
                guest_launch_measurements: measurements
                    .iter()
                    .map(|m| GuestLaunchMeasurement {
                        measurement: m.as_ref().to_vec(),
                        metadata: None,
                    })
                    .collect(),
            }),
        }
    }

    fn create_replica_record_without_measurements(
        replica_version_id: &str,
        package_hash: &str,
    ) -> ReplicaVersionRecord {
        ReplicaVersionRecord {
            replica_version_id: Some(replica_version_id.to_string()),
            release_package_sha256_hex: package_hash.to_string(),
            release_package_urls: vec![],
            guest_launch_measurements: None,
        }
    }

    #[test]
    fn test_get_guest_launch_measurements() {
        let registry_version = RegistryVersion::from(42);

        let measurement1 = [1, 2, 3, 4, 5];
        let measurement2 = [6, 7, 8, 9, 10];
        let measurement3 = [11, 12, 13, 14, 15];
        let measurement4 = [16, 17, 18, 19, 20]; // From removed version

        let replica_versions_and_records = vec![
            (
                "version1",
                create_replica_record("version1", "12345", &[measurement1, measurement2]),
            ),
            (
                "version2",
                create_replica_record("version2", "abcde", &[measurement3]),
            ),
            (
                "version3",
                create_replica_record("version3", "99999", &[measurement4]),
            ),
            (
                "version4",
                create_replica_record_without_measurements("version4", "424242"),
            ),
        ];

        // Set up registry data provider
        let data_provider = ProtoRegistryDataProvider::new();

        // Add replica version records
        for (replica_version_id, record) in &replica_versions_and_records {
            data_provider
                .add(
                    &make_replica_version_key(replica_version_id),
                    registry_version,
                    Some(record.clone()),
                )
                .expect("Failed to add replica version record");
        }

        // Later, remove a version
        data_provider
            .add(
                &make_replica_version_key("version3"),
                registry_version + RegistryVersion::from(1),
                None::<ReplicaVersionRecord>,
            )
            .expect("Failed to remove replica version record");

        // Create registry client and update to latest version
        let registry_client = FakeRegistryClient::new(Arc::new(data_provider));
        registry_client.update_to_latest_version();

        // Check that all measurements initially existed
        let result = registry_client.get_guest_launch_measurements(registry_version);
        assert_eq!(
            result,
            Ok(vec![
                measurement1.to_vec(),
                measurement2.to_vec(),
                measurement3.to_vec(),
                measurement4.to_vec()
            ])
        );

        // Check that one is successfully removed, along with the version
        let result = registry_client
            .get_guest_launch_measurements(registry_version + RegistryVersion::from(1));
        assert_eq!(
            result,
            Ok(vec![
                measurement1.to_vec(),
                measurement2.to_vec(),
                measurement3.to_vec()
            ])
        );
    }
}
