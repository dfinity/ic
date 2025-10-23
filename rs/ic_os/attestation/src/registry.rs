use ic_interfaces_registry::RegistryClient;
use ic_registry_client_helpers::blessed_replica_version::BlessedReplicaVersionRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::ReplicaVersion;
use std::str::FromStr;

pub fn get_blessed_guest_launch_measurements_from_registry(
    nns_registry_client: &dyn RegistryClient,
) -> Result<Vec<Vec<u8>>, String> {
    let latest_registry_version = nns_registry_client.get_latest_version();
    let blessed_replica_versions = nns_registry_client
        .get_blessed_replica_versions(latest_registry_version)
        .map_err(|err| format!("Failed to get blessed replica versions: {err}"))?
        .ok_or_else(|| "Blessed replica versions not found in registry".to_string())?;

    let measurements = blessed_replica_versions
        .blessed_version_ids
        .iter()
        .filter_map(|version_id| ReplicaVersion::from_str(version_id).ok())
        .filter_map(|replica_version| {
            nns_registry_client
                .get_replica_version_record_from_version_id(
                    &replica_version,
                    latest_registry_version,
                )
                .ok()
                .flatten()
        })
        .flat_map(|record| {
            record
                .guest_launch_measurements
                .unwrap_or_default()
                .guest_launch_measurements
        })
        .map(|measurement| {
            measurement
                .encoded_measurement
                .map(|encoded| {
                    hex::decode(encoded)
                        .map_err(|err| format!("Failed to decode replica measurement: {err}"))
                })
                .unwrap_or_else(|| {
                    #[allow(deprecated)]
                    Ok(measurement.measurement)
                })
        })
        .collect::<Result<_, _>>()?;

    Ok(measurements)
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation_testing::registry::setup_mock_registry_client_with_blessed_versions;
    use ic_protobuf::registry::replica_version::v1::{
        GuestLaunchMeasurement, GuestLaunchMeasurements, ReplicaVersionRecord,
    };
    use ic_types::RegistryVersion;

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
                        #[allow(deprecated)]
                        measurement: m.as_ref().to_vec(),
                        metadata: None,
                        encoded_measurement: Some(hex::encode(m)),
                    })
                    .collect(),
            }),
        }
    }

    #[test]
    fn test_get_blessed_guest_launch_measurements_from_registry() {
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

        let mock_registry_client = setup_mock_registry_client_with_blessed_versions(
            registry_version,
            &blessed_versions,
            &replica_versions_and_records,
        );

        assert_eq!(
            get_blessed_guest_launch_measurements_from_registry(&mock_registry_client),
            Ok(vec![
                measurement1.to_vec(),
                measurement2.to_vec(),
                measurement3.to_vec()
            ])
        );
    }
}
