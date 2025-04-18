use ic_interfaces_registry::RegistryClient;
use ic_registry_client_helpers::blessed_replica_version::BlessedReplicaVersionRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::ReplicaVersion;
use itertools::Itertools;
use std::str::FromStr;

pub fn get_blessed_guest_launch_measurements_from_registry(
    nns_registry_client: &dyn RegistryClient,
) -> Result<Vec<Vec<u8>>, String> {
    // return Ok(vec![
    //     vec![
    //         41, 13, 130, 179, 117, 27, 52, 196, 173, 178, 226, 226, 106, 162, 175, 86, 203, 243,
    //         144, 132, 170, 249, 211, 45, 128, 85, 199, 188, 255, 180, 203, 106, 209, 28, 68, 225,
    //         92, 203, 191, 188, 155, 150, 215, 113, 93, 97, 28, 29,
    //     ],
    //     vec![
    //         27, 83, 44, 231, 125, 5, 99, 245, 162, 210, 90, 73, 242, 245, 85, 143, 57, 54, 176, 93,
    //         129, 226, 185, 216, 103, 134, 201, 183, 216, 177, 198, 93, 4, 156, 13, 18, 181, 181,
    //         202, 124, 220, 148, 199, 222, 96, 124, 108, 19,
    //     ],
    // ]);
    let latest_registry_version = nns_registry_client.get_latest_version();
    let blessed_replica_versions = nns_registry_client
        .get_blessed_replica_versions(latest_registry_version)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "Blessed replica versions are not available".to_string())?;

    let measurements = blessed_replica_versions
        .blessed_version_ids
        .iter()
        .flat_map(|version_id| ReplicaVersion::from_str(version_id))
        .flat_map(|replica_version| {
            nns_registry_client.get_replica_version_record_from_version_id(
                &replica_version,
                latest_registry_version,
            )
            // TODO: consider logging errors
        })
        .flatten()
        .flat_map(|version_record| version_record.guest_launch_measurements)
        .map(|measurement| measurement.measurement)
        .collect_vec();

    Ok(measurements)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces_registry_mocks::MockRegistryClient;
    use ic_protobuf::registry::replica_version::v1::{
        BlessedReplicaVersions, GuestLaunchMeasurement, ReplicaVersionRecord,
    };
    use ic_registry_keys::{make_blessed_replica_versions_key, make_replica_version_key};
    use ic_types::RegistryVersion;
    use mockall::predicate::eq;
    use prost::Message;

    #[test]
    fn test_get_blessed_guest_launch_measurements_from_registry() {
        let registry_version = RegistryVersion::from(42);
        let blessed_versions = ["version1", "version2"];

        let measurement1 = [1, 2, 3, 4, 5];
        let measurement2 = [6, 7, 8, 9, 10];
        let measurement3 = [11, 12, 13, 14, 15];
        let measurement4 = [16, 17, 18, 19, 20];

        let replica_versions_and_records = vec![
            (
                "version1",
                create_replica_record("12345", &[measurement1, measurement2]),
            ),
            ("version2", create_replica_record("abcde", &[measurement3])),
            ("version3", create_replica_record("99999", &[measurement4])),
        ];

        let mock_registry_client = setup_mock_registry_client(
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

    fn create_replica_record(
        package_hash: &str,
        measurements: &[impl AsRef<[u8]>],
    ) -> ReplicaVersionRecord {
        ReplicaVersionRecord {
            release_package_sha256_hex: package_hash.to_string(),
            release_package_urls: vec![],
            guest_launch_measurements: measurements
                .iter()
                .map(|m| GuestLaunchMeasurement {
                    measurement: m.as_ref().to_vec(),
                    metadata: None,
                })
                .collect(),
        }
    }

    fn setup_mock_registry_client(
        registry_version: RegistryVersion,
        blessed_replica_ids: &[&str],
        replica_versions_and_records: &[(&str, ReplicaVersionRecord)],
    ) -> MockRegistryClient {
        let mut mock_client = MockRegistryClient::new();

        mock_client
            .expect_get_latest_version()
            .return_const(registry_version);

        let blessed_versions = BlessedReplicaVersions {
            blessed_version_ids: blessed_replica_ids
                .iter()
                .map(|id| id.to_string())
                .collect(),
        };

        mock_client
            .expect_get_value()
            .with(
                eq(make_blessed_replica_versions_key()),
                eq(registry_version),
            )
            .return_once(move |_, _| Ok(Some(blessed_versions.encode_to_vec())));

        for (version_key, record) in replica_versions_and_records {
            let encoded_record = record.encode_to_vec();
            mock_client
                .expect_get_value()
                .with(
                    eq(make_replica_version_key(version_key)),
                    eq(registry_version),
                )
                .return_once(move |_, _| Ok(Some(encoded_record)));
        }

        mock_client
    }
}
