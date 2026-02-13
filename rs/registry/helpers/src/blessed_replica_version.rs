use crate::deserialize_registry_value;
use crate::subnet::SubnetRegistry;
use ic_base_types::RegistryVersion;
use ic_interfaces_registry::{RegistryClient, RegistryClientResult};
use ic_protobuf::registry::replica_version::v1::BlessedReplicaVersions;
use ic_registry_keys::make_blessed_replica_versions_key;
use ic_types::ReplicaVersion;
use std::str::FromStr;

pub trait BlessedReplicaVersionRegistry {
    fn get_blessed_replica_versions(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<BlessedReplicaVersions>;

    /// Returns all guest launch measurements from all blessed replica versions.
    ///
    /// This method fetches the blessed replica versions from the registry at the given version,
    /// then retrieves the replica version records for each blessed version, and finally collects
    /// all guest launch measurements from those records.
    fn get_blessed_guest_launch_measurements(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<Vec<u8>>, String>;
}

impl<T: RegistryClient + ?Sized> BlessedReplicaVersionRegistry for T {
    fn get_blessed_replica_versions(
        &self,
        version: RegistryVersion,
    ) -> RegistryClientResult<BlessedReplicaVersions> {
        deserialize_registry_value(self.get_value(&make_blessed_replica_versions_key(), version))
    }

    fn get_blessed_guest_launch_measurements(
        &self,
        version: RegistryVersion,
    ) -> Result<Vec<Vec<u8>>, String> {
        let blessed_replica_versions = self
            .get_blessed_replica_versions(version)
            .map_err(|err| format!("Failed to get blessed replica versions: {err}"))?
            .ok_or_else(|| "Blessed replica versions not found in registry".to_string())?;

        let measurements = blessed_replica_versions
            .blessed_version_ids
            .iter()
            .filter_map(|version_id| ReplicaVersion::from_str(version_id).ok())
            .filter_map(|replica_version| {
                self.get_replica_version_record_from_version_id(&replica_version, version)
                    .ok()
                    .flatten()
            })
            .flat_map(|record| {
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
        package_hash: &str,
        measurements: &[impl AsRef<[u8]>],
    ) -> ReplicaVersionRecord {
        ReplicaVersionRecord {
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

    #[test]
    fn test_get_blessed_guest_launch_measurements() {
        let registry_version = RegistryVersion::from(42);
        let blessed_versions = ["version1", "version2"];

        let measurement1 = [1, 2, 3, 4, 5];
        let measurement2 = [6, 7, 8, 9, 10];
        let measurement3 = [11, 12, 13, 14, 15];
        let measurement4 = [16, 17, 18, 19, 20]; // From unblessed version

        let replica_versions_and_records = vec![
            (
                "version1",
                create_replica_record("12345", &[measurement1, measurement2]),
            ),
            ("version2", create_replica_record("abcde", &[measurement3])),
            ("version3", create_replica_record("99999", &[measurement4])),
        ];

        // Set up registry data provider
        let data_provider = ProtoRegistryDataProvider::new();

        // Add blessed replica versions
        let blessed_versions_proto = BlessedReplicaVersions {
            blessed_version_ids: blessed_versions.iter().map(|x| x.to_string()).collect(),
        };
        data_provider
            .add(
                &make_blessed_replica_versions_key(),
                registry_version,
                Some(blessed_versions_proto),
            )
            .expect("Failed to add blessed replica versions");

        // Add replica version records
        for (version_id, record) in &replica_versions_and_records {
            data_provider
                .add(
                    &make_replica_version_key(version_id),
                    registry_version,
                    Some(record.clone()),
                )
                .expect("Failed to add replica version record");
        }

        // Create registry client and update to latest version
        let registry_client = FakeRegistryClient::new(Arc::new(data_provider));
        registry_client.update_to_latest_version();

        let result = registry_client.get_blessed_guest_launch_measurements(registry_version);

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
