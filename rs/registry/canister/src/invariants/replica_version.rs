use std::collections::BTreeSet;

use crate::invariants::common::{
    InvariantCheckError, RegistrySnapshot, assert_valid_urls_and_hash,
    get_api_boundary_node_records_from_snapshot, get_subnet_ids_from_snapshot,
    get_value_from_snapshot,
};

use ic_base_types::SubnetId;
use ic_protobuf::registry::{
    replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    subnet::v1::SubnetRecord,
    unassigned_nodes_config::v1::UnassignedNodesConfigRecord,
};
use ic_registry_keys::{
    make_blessed_replica_versions_key, make_replica_version_key, make_subnet_record_key,
    make_unassigned_nodes_config_record_key,
};
use prost::Message;

/// A predicate on the replica version records contained in a registry
/// snapshot.
///
/// For each replica version that is either referred to in a SubnetRecord
/// of a subnet listed in the subnet list, that is in use by an API boundary node,
/// that is used by the unassigned nodes, or that is contained
/// the BlessedReplicaVersions-List, the following is checked:
///
/// * The corresponding ReplicaVersionRecord exists.
/// * Each URL is well-formed.
/// * Release package hash is a well-formed hex-encoded SHA256 value.
pub(crate) fn check_replica_version_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let mut versions_in_use = get_all_replica_versions_of_subnets(snapshot);
    let unassigned_version_id = snapshot
        .get(make_unassigned_nodes_config_record_key().as_bytes())
        .map(|bytes| {
            let unassigned_nodes_config =
                UnassignedNodesConfigRecord::decode(bytes.as_slice()).unwrap();
            unassigned_nodes_config.replica_version
        });
    if let Some(version) = unassigned_version_id {
        versions_in_use.insert(version);
    }
    versions_in_use.append(&mut get_all_api_boundary_node_versions(snapshot));

    let blessed_version_ids = snapshot
        .get(make_blessed_replica_versions_key().as_bytes())
        .map(|bytes| {
            let version_list = BlessedReplicaVersions::decode(bytes.as_slice()).unwrap();
            version_list.blessed_version_ids
        })
        .unwrap_or_default();

    let num_blessed = blessed_version_ids.len();
    let blessed_set = BTreeSet::from_iter(blessed_version_ids);
    assert!(
        blessed_set.len() == num_blessed,
        "A version was blessed multiple times."
    );
    assert!(
        blessed_set.is_superset(&versions_in_use),
        "Using a version that isn't blessed. Blessed versions: {blessed_set:?}, in use: {versions_in_use:?}."
    );
    assert!(
        blessed_set.iter().all(|v| !v.trim().is_empty()),
        "Blessed an empty version ID."
    );

    for version in blessed_set {
        let r = get_replica_version_record(snapshot, version);

        // Check whether release package URLs (update image) and corresponding hash is well-formed.
        // As file-based URLs are only used in test-deployments, we disallow file:/// URLs.
        assert_valid_urls_and_hash(
            &r.release_package_urls,
            &r.release_package_sha256_hex,
            false, // allow_file_url
        );

        // Check that all measured versions are valid
        if let Some(Err(defects)) = r.guest_launch_measurements.map(|v| v.validate()) {
            panic!("guest_launch_measurements are not valid. Defects: {defects:?}");
        }
    }

    Ok(())
}

fn get_replica_version_record(
    snapshot: &RegistrySnapshot,
    version: String,
) -> ReplicaVersionRecord {
    get_value_from_snapshot(snapshot, make_replica_version_key(version.clone()))
        .unwrap_or_else(|| panic!("Could not find replica version: {version}"))
}

fn get_subnet_record(snapshot: &RegistrySnapshot, subnet_id: SubnetId) -> SubnetRecord {
    get_value_from_snapshot(snapshot, make_subnet_record_key(subnet_id))
        .unwrap_or_else(|| panic!("Could not get subnet record for subnet: {subnet_id}"))
}

/// Returns the list of replica versions where each version is referred to
/// by at least one subnet.
fn get_all_replica_versions_of_subnets(snapshot: &RegistrySnapshot) -> BTreeSet<String> {
    get_subnet_ids_from_snapshot(snapshot)
        .iter()
        .map(|subnet_id| get_subnet_record(snapshot, *subnet_id).replica_version_id)
        .collect()
}

/// Returns the list of all replica versions that are currently in use by the API boundary nodes.
fn get_all_api_boundary_node_versions(snapshot: &RegistrySnapshot) -> BTreeSet<String> {
    get_api_boundary_node_records_from_snapshot(snapshot)
        .values()
        .map(|node_record| node_record.version.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::common::test_helpers::invariant_compliant_registry;

    use super::*;
    use canister_test::PrincipalId;
    use ic_protobuf::registry::replica_version::v1::{
        GuestLaunchMeasurement, GuestLaunchMeasurementMetadata, GuestLaunchMeasurements,
    };
    use ic_registry_transport::{insert, upsert};
    use ic_types::ReplicaVersion;
    use prost::Message;

    const MOCK_HASH: &str = "C0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEED00D";
    const MOCK_URL: &str = "http://release_package.tar.gz";

    fn check_bless_version(versions: Vec<String>) {
        let registry = invariant_compliant_registry(0);

        let key = make_blessed_replica_versions_key();
        let value = BlessedReplicaVersions {
            blessed_version_ids: versions,
        }
        .encode_to_vec();

        let mutation = vec![insert(key.as_bytes(), value)];
        registry.check_global_state_invariants(&mutation);
    }

    #[test]
    #[should_panic(expected = "Blessed an empty version ID.")]
    fn panic_when_blessing_empty_version() {
        check_bless_version(vec![ReplicaVersion::default().into(), "".into()]);
    }

    #[test]
    #[should_panic(expected = "Blessed an empty version ID.")]
    fn panic_when_blessing_whitespace_version() {
        check_bless_version(vec![ReplicaVersion::default().into(), "  ".into()]);
    }

    #[test]
    #[should_panic(expected = "A version was blessed multiple times.")]
    fn panic_when_blessing_same_version_twice() {
        check_bless_version(vec!["version_a".into(), "version_a".into()]);
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't blessed.")]
    fn panic_when_retiring_a_version_in_use() {
        check_bless_version(vec![]);
    }

    #[test]
    #[should_panic(expected = "Could not find replica version: unknown")]
    fn panic_when_blessing_unknown_version() {
        check_bless_version(vec![ReplicaVersion::default().into(), "unknown".into()]);
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't blessed.")]
    fn panic_when_using_unelected_version() {
        let registry = invariant_compliant_registry(0);

        let list = registry.get_subnet_list_record();
        let nns_id = SubnetId::from(PrincipalId::try_from(list.subnets.first().unwrap()).unwrap());
        let mut subnet = registry.get_subnet_or_panic(nns_id);
        subnet.replica_version_id = "unelected".into();

        let new_subnet = upsert(
            make_subnet_record_key(nns_id).into_bytes(),
            subnet.encode_to_vec(),
        );
        registry.check_global_state_invariants(&[new_subnet]);
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't blessed.")]
    fn panic_when_retiring_unassigned_nodes_version() {
        let mut registry = invariant_compliant_registry(0);

        let replica_version_id = "unassigned_version".to_string();
        let replica_version = ReplicaVersionRecord {
            release_package_sha256_hex: "".to_string(),
            release_package_urls: vec![],
            guest_launch_measurements: None,
        };
        let blessed_replica_version = BlessedReplicaVersions {
            blessed_version_ids: vec![ReplicaVersion::default().into(), replica_version_id.clone()],
        };
        let unassigned_nodes_config = UnassignedNodesConfigRecord {
            ssh_readonly_access: vec![],
            replica_version: replica_version_id.clone(),
        };

        let init = vec![
            insert(
                make_replica_version_key(replica_version_id).as_bytes(),
                replica_version.encode_to_vec(),
            ),
            upsert(
                make_blessed_replica_versions_key().as_bytes(),
                blessed_replica_version.encode_to_vec(),
            ),
            insert(
                make_unassigned_nodes_config_record_key(),
                unassigned_nodes_config.encode_to_vec(),
            ),
        ];
        registry.maybe_apply_mutation_internal(init);

        let key = make_blessed_replica_versions_key();

        let value = BlessedReplicaVersions {
            blessed_version_ids: vec![ReplicaVersion::default().into()],
        }
        .encode_to_vec();

        let mutation = vec![insert(key.as_bytes(), value)];
        registry.check_global_state_invariants(&mutation);
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't blessed.")]
    fn panic_when_using_unelected_unassigned_version() {
        let registry = invariant_compliant_registry(0);

        let key = make_unassigned_nodes_config_record_key();
        let value = UnassignedNodesConfigRecord {
            ssh_readonly_access: vec![],
            replica_version: "unelected".into(),
        }
        .encode_to_vec();

        let mutation = vec![insert(key.as_bytes(), value)];
        registry.check_global_state_invariants(&mutation);
    }

    fn check_replica_version(hash: &str, urls: Vec<String>) {
        let registry = invariant_compliant_registry(0);

        let key = make_replica_version_key(ReplicaVersion::default());
        let value = ReplicaVersionRecord {
            release_package_sha256_hex: hash.into(),
            release_package_urls: urls,
            guest_launch_measurements: Some(GuestLaunchMeasurements {
                guest_launch_measurements: vec![GuestLaunchMeasurement {
                    measurement: vec![0x01, 0x02, 0x03],
                    metadata: Some(GuestLaunchMeasurementMetadata {
                        kernel_cmdline: Some("foo=bar".to_string()),
                    }),
                }],
            }),
        }
        .encode_to_vec();

        let mutation = vec![upsert(key.as_bytes(), value)];
        registry.check_global_state_invariants(&mutation);
    }

    #[test]
    #[should_panic(expected = "Either both, an url and a hash must be set, or none.")]
    fn panic_when_only_hash_is_set() {
        check_replica_version(MOCK_HASH, vec![]);
    }

    #[test]
    #[should_panic(expected = "Either both, an url and a hash must be set, or none.")]
    fn panic_when_only_url_is_set() {
        check_replica_version("", vec![MOCK_URL.into()]);
    }

    #[test]
    #[should_panic(expected = "Release package URL abcde is not valid")]
    fn panic_when_url_is_invalid() {
        check_replica_version(MOCK_HASH, vec!["abcde".into()]);
    }

    #[test]
    #[should_panic(expected = "Hash contains at least one invalid character")]
    fn panic_when_hash_is_invalid() {
        check_replica_version("XYZ", vec![MOCK_URL.into()]);
    }

    #[test]
    #[should_panic(expected = "guest_launch_measurements must not be an empty vector")]
    fn panic_when_measurements_are_empty() {
        let registry = invariant_compliant_registry(0);

        let key = make_replica_version_key(ReplicaVersion::default());
        let value = ReplicaVersionRecord {
            release_package_sha256_hex: MOCK_HASH.into(),
            release_package_urls: vec![MOCK_URL.into()],
            guest_launch_measurements: Some(GuestLaunchMeasurements {
                guest_launch_measurements: vec![],
            }),
        }
        .encode_to_vec();

        let mutation = vec![upsert(key.as_bytes(), value)];
        registry.check_global_state_invariants(&mutation);
    }

    #[test]
    fn empty_hash_and_url() {
        check_replica_version("", vec![]);
    }

    #[test]
    fn set_hash_and_url() {
        check_replica_version(MOCK_HASH, vec![MOCK_URL.into()]);
    }
}
