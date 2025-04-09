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
        .flat_map(|version_record| version_record.guest_launch_measurement_sha256_hex)
        .map(|measurement| measurement.into_bytes())
        .collect_vec();

    if measurements.is_empty() {
        return Err("No blessed guest launch measurements found".to_string());
    }

    Ok(measurements)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_interfaces_registry::RegistryValue;
    use ic_interfaces_registry_mocks::MockRegistryClient;
    use ic_protobuf::registry::replica_version::v1::BlessedReplicaVersions;

    #[test]
    fn test_get_blessed_guest_launch_measurements_from_registry() {
        //     let mut mock_registry_client = MockRegistryClient::new();
        //
        //     let blessed_replica_versions = BlessedReplicaVersions {
        //         blessed_version_ids: vec!["foo".to_string(), "bar".to_string(), "no_data".to_string()],
        //     };
        //
        //     mock_registry_client.expect_get_value()
        //         .withf(|key, version| {
        //             key == make_replica_version_key() &&
        //             version == &ic_base_types::RegistryVersion::from(0)
        //         })
        //         .returning(|key, version| {
        //         let mut v = Vec::new();
        //         blessed_replica_versions.encode(&mut v).unwrap();
        //         Ok(Some(v))
        //     });
        //
        //     let result = get_blessed_guest_launch_measurements_from_registry(&mock_registry_client);
        //     assert!(result.is_ok());
    }
}
