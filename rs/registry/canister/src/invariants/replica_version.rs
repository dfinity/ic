use std::collections::BTreeSet;

use crate::{
    flags::is_blank_replica_version_id_for_cloud_engines_enabled,
    invariants::common::{
        InvariantCheckError, RegistrySnapshot, assert_valid_urls_and_hash,
        get_all_replica_version_records, get_api_boundary_node_records_from_snapshot,
        get_subnet_ids_from_snapshot, get_value_from_snapshot,
    },
};

use ic_base_types::SubnetId;
use ic_protobuf::registry::{
    replica_version::v1::ReplicaVersionRecord,
    standard_engine_replica_version::v1::StandardEngineReplicaVersionRecord,
    subnet::v1::{SubnetRecord, SubnetType},
    unassigned_nodes_config::v1::UnassignedNodesConfigRecord,
};
use ic_registry_keys::{
    make_replica_version_key, make_standard_engine_replica_version_record_key,
    make_subnet_record_key, make_unassigned_nodes_config_record_key,
};
use prost::Message;

/// A predicate on the replica version records contained in a registry
/// snapshot.
///
/// For each replica version that is either referred to in a SubnetRecord
/// of a subnet listed in the subnet list, that is in use by an API boundary node,
/// or that is used by the unassigned nodes, the following is checked:
///
/// * The corresponding ReplicaVersionRecord exists.
/// * Each URL is well-formed.
/// * Release package hash is a well-formed hex-encoded SHA256 value.
///
/// Exception: a CloudEngine can have a blank replica_version_id in its
/// SubnetRecord if there is a StandardEngineReplicaVersionRecord. As of July
/// 22, 2026, this feature is disabled via a flag (but the plan is to enable it
/// in the not too distant future).
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
    versions_in_use.append(&mut get_all_standard_engine_replica_versions(snapshot));
    versions_in_use.append(&mut get_all_api_boundary_node_versions(snapshot));

    let elected_set: BTreeSet<_> = get_all_replica_version_records(snapshot)
        .into_keys()
        .collect();
    assert!(
        elected_set.is_superset(&versions_in_use),
        "Using a version that isn't elected. Elected versions: {elected_set:?}, in use: {versions_in_use:?}."
    );
    assert!(
        elected_set.iter().all(|v| !v.trim().is_empty()),
        "Elected an empty version ID."
    );

    for version in elected_set {
        let r = get_replica_version_record(snapshot, version);

        // Check whether release package URLs (update image) and corresponding hash are well-formed.
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
    let cloud_engines_are_allowed_to_have_blank_replica_version_id =
        is_blank_replica_version_id_for_cloud_engines_enabled()
            && snapshot
                .get(make_standard_engine_replica_version_record_key().as_bytes())
                .is_some();

    get_subnet_ids_from_snapshot(snapshot)
        .iter()
        .filter_map(|subnet_id| {
            let SubnetRecord {
                replica_version_id,
                subnet_type,
                ..
            } = get_subnet_record(snapshot, *subnet_id);

            if !replica_version_id.is_empty() {
                // For non-CloudEngines, this is normal (because it is
                // required). CloudEngines can also end up here.
                return Some(replica_version_id);
            }

            if subnet_type == SubnetType::CloudEngine as i32
                && cloud_engines_are_allowed_to_have_blank_replica_version_id
            {
                // For CloudEngines, this is normal (because this is allowed and
                // typical).
                return None;
            }

            // Most likely, this will eventually lead to an explosion, because
            // at this point, replica_version_id is empty, and in practice, we
            // would have no elected replica version with an ID of length 0.
            Some(replica_version_id)
        })
        .collect()
}

/// Returns the list of all replica versions that are currently in use by the API boundary nodes.
fn get_all_api_boundary_node_versions(snapshot: &RegistrySnapshot) -> BTreeSet<String> {
    get_api_boundary_node_records_from_snapshot(snapshot)
        .values()
        .map(|node_record| node_record.version.clone())
        .collect()
}

/// Returns the replica versions referenced by the
/// StandardEngineReplicaVersionRecord (i.e. new_replica_version_id and
/// old_replica_version_id).
fn get_all_standard_engine_replica_versions(snapshot: &RegistrySnapshot) -> BTreeSet<String> {
    snapshot
        .get(make_standard_engine_replica_version_record_key().as_bytes())
        .map(|bytes| {
            let record = StandardEngineReplicaVersionRecord::decode(bytes.as_slice()).unwrap();
            [record.new_replica_version_id, record.old_replica_version_id]
        })
        .into_iter()
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{
        common::test_helpers::{
            invariant_compliant_registry, prepare_registry_with_cloud_engine_subnet,
        },
        flags::{
            temporarily_disable_blank_replica_version_id_for_cloud_engines,
            temporarily_enable_blank_replica_version_id_for_cloud_engines,
        },
        registry::Registry,
    };

    use super::*;
    use canister_test::PrincipalId;
    use ic_protobuf::registry::replica_version::v1::{
        GuestLaunchMeasurement, GuestLaunchMeasurementMetadata, GuestLaunchMeasurements,
    };
    use ic_registry_transport::{delete, insert, pb::v1::RegistryMutation, upsert};
    use ic_types::ReplicaVersion;
    use prost::Message;

    const MOCK_HASH: &str = "C0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEEC0FFEED00D";
    const MOCK_URL: &str = "http://release_package.tar.gz";

    // Replica version IDs are git commit IDs (pointing to the source code used
    // to build the Replica).
    const REPLICA_VERSION_ID_1: &str = "eb3ab997954f2a91db8a42f84132cf37078d481c";
    const REPLICA_VERSION_ID_2: &str = "63d086714a1e2bc6b0615008d5582f527d554cd3";

    fn elect_version_mutations(versions: Vec<String>) -> Vec<RegistryMutation> {
        versions
            .into_iter()
            .map(|v| {
                insert(
                    make_replica_version_key(v).as_bytes(),
                    ReplicaVersionRecord::default().encode_to_vec(),
                )
            })
            .collect()
    }

    #[test]
    #[should_panic(expected = "Elected an empty version ID.")]
    fn panic_when_electing_empty_version() {
        let registry = invariant_compliant_registry(0);

        let mutations = elect_version_mutations(vec!["".into()]);

        registry.check_global_state_invariants(&mutations);
    }

    #[test]
    #[should_panic(expected = "Elected an empty version ID.")]
    fn panic_when_electing_whitespace_version() {
        let registry = invariant_compliant_registry(0);

        let mutations = elect_version_mutations(vec!["  ".into()]);

        registry.check_global_state_invariants(&mutations);
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't elected.")]
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
    #[should_panic(expected = "Using a version that isn't elected.")]
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

    #[test]
    fn test_can_update_standard_engine_replica_version_record() {
        // Step 1: Prepare the world. In particular, elect a couple of replica versions.
        let mut registry = invariant_compliant_registry(0);
        registry.maybe_apply_mutation_internal(elect_version_mutations(vec![
            REPLICA_VERSION_ID_1.to_string(),
            REPLICA_VERSION_ID_2.to_string(),
        ]));

        // Step 2: Run the code under test.

        // Prepare the mutation that's supposed to succeed.
        let key = make_standard_engine_replica_version_record_key();
        let value = StandardEngineReplicaVersionRecord {
            new_replica_version_id: REPLICA_VERSION_ID_1.to_string(),
            old_replica_version_id: REPLICA_VERSION_ID_2.to_string(),
            deployment_progress: 0.1,
        }
        .encode_to_vec();

        // Attempt the mutation.
        let mutation = vec![insert(key.as_bytes(), value)];
        registry.check_global_state_invariants(&mutation);

        // Step 3: Verify result(s).
        // The implicit assertion here is the previous line did not panic.
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't elected.")]
    fn panic_when_new_replica_version_is_not_elected_in_standard_engine_replica_version_record() {
        // Step 1: Prepare the world. Elect old, but not new.
        let mut registry = invariant_compliant_registry(0);
        registry.maybe_apply_mutation_internal(elect_version_mutations(vec![
            REPLICA_VERSION_ID_1.to_string(),
        ]));

        // Step 2: Run the code under test.

        // Prepare mutation.
        let key = make_standard_engine_replica_version_record_key();
        let value = StandardEngineReplicaVersionRecord {
            new_replica_version_id: "garbage".to_string(), // <- This is the bomb.
            old_replica_version_id: REPLICA_VERSION_ID_1.to_string(),
            deployment_progress: 0.1,
        }
        .encode_to_vec();

        // Attempt mutation.
        let mutation = vec![insert(key.as_bytes(), value)];
        registry.check_global_state_invariants(&mutation);

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't elected.")]
    fn panic_when_old_replica_version_is_not_elected_in_standard_engine_replica_version_record() {
        // Step 1: Prepare the world. Elect new, but not old.
        // (Same initial state as previous test.)
        let mut registry = invariant_compliant_registry(0);
        registry.maybe_apply_mutation_internal(elect_version_mutations(vec![
            REPLICA_VERSION_ID_1.to_string(),
        ]));

        // Step 2: Run the code under test.

        // Prepare mutation.
        let key = make_standard_engine_replica_version_record_key();
        let value = StandardEngineReplicaVersionRecord {
            new_replica_version_id: REPLICA_VERSION_ID_1.to_string(),
            old_replica_version_id: "garbage".to_string(), // <- This is the bomb.
            deployment_progress: 0.1,
        }
        .encode_to_vec();

        // Attempt mutation.
        let mutation = vec![insert(key.as_bytes(), value)];
        registry.check_global_state_invariants(&mutation);

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }

    /// Adds a CloudEngine subnet (subnet_type, cycles cost schedule, member
    /// node reward types, and crypto/CUP material all set up) to the given
    /// registry. Its replica_version_id is left as the default, which is
    /// non-blank. Returns the new subnet's id.
    fn add_cloud_engine_subnet(registry: &mut Registry) -> SubnetId {
        let (cloud_engine_request, subnet_id) = prepare_registry_with_cloud_engine_subnet(1, 1);
        registry.maybe_apply_mutation_internal(cloud_engine_request.mutations);

        subnet_id
    }

    /// Returns a collection of mutations that blanks out the given subnet's
    /// replica_version_id.
    fn blank_replica_version_id_mutation(
        registry: &Registry,
        subnet_id: SubnetId,
    ) -> Vec<RegistryMutation> {
        let mut subnet = registry.get_subnet_or_panic(subnet_id);
        subnet.replica_version_id = "".to_string();

        vec![upsert(
            make_subnet_record_key(subnet_id).into_bytes(),
            subnet.encode_to_vec(),
        )]
    }

    /// One thing not mentioned in the name is that
    /// StandardEngineReplicaVersionRecord must exist (and this feature must be
    /// enabled via flag).
    #[test]
    fn test_blank_replica_version_id_is_allowed() {
        // Step 1: Prepare the world.

        let _restore_on_drop = temporarily_enable_blank_replica_version_id_for_cloud_engines();
        let mut registry = invariant_compliant_registry(0);

        // Elect replica versions 1 and 2.
        registry.maybe_apply_mutation_internal(elect_version_mutations(vec![
            REPLICA_VERSION_ID_1.to_string(),
            REPLICA_VERSION_ID_2.to_string(),
        ]));

        // Upgrade 10% of CloudEngines to replica version 2 (from version 1).
        registry.maybe_apply_mutation_internal(vec![insert(
            make_standard_engine_replica_version_record_key().as_bytes(),
            StandardEngineReplicaVersionRecord {
                new_replica_version_id: REPLICA_VERSION_ID_2.to_string(),
                old_replica_version_id: REPLICA_VERSION_ID_1.to_string(),
                deployment_progress: 0.1,
            }
            .encode_to_vec(),
        )]);

        // Create a Cloud Engine.
        let subnet_id = add_cloud_engine_subnet(&mut registry);

        // Step 2: Run the code under test.
        let mutation = blank_replica_version_id_mutation(&registry, subnet_id);
        registry.check_global_state_invariants(&mutation);

        // Step 3: Verify result(s).
        // The implicit assertion is that the previous line did not panic.
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't elected.")]
    fn panic_when_blank_replica_version_id_is_not_enabled_yet() {
        // Step 1: Prepare the world. The only difference compared to the
        // previous test is that here, the feature is DISABLED.
        let _restore_on_drop = temporarily_disable_blank_replica_version_id_for_cloud_engines();
        let mut registry = invariant_compliant_registry(0);
        registry.maybe_apply_mutation_internal(elect_version_mutations(vec![
            REPLICA_VERSION_ID_1.to_string(),
            REPLICA_VERSION_ID_2.to_string(),
        ]));
        registry.maybe_apply_mutation_internal(vec![insert(
            make_standard_engine_replica_version_record_key().as_bytes(),
            StandardEngineReplicaVersionRecord {
                new_replica_version_id: REPLICA_VERSION_ID_2.to_string(),
                old_replica_version_id: REPLICA_VERSION_ID_1.to_string(),
                deployment_progress: 0.1,
            }
            .encode_to_vec(),
        )]);
        let subnet_id = add_cloud_engine_subnet(&mut registry);

        // Step 2: Run the code under test. Same as the previous test.
        let mutation = blank_replica_version_id_mutation(&registry, subnet_id);
        registry.check_global_state_invariants(&mutation);

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
        // Unlike the previous test where the nominal behavior is NO panic.
    }

    /// It is fine for there to be no standard engine replica version if there
    /// are no CloudEngines, but in general, there would be, so the name of this
    /// test does not mention this "and the sun must exist" condition.
    #[test]
    #[should_panic(expected = "Using a version that isn't elected.")]
    fn panic_when_there_is_no_standard_replica_version() {
        // Step 1: Prepare the world.
        let _restore_on_drop = temporarily_enable_blank_replica_version_id_for_cloud_engines();
        let mut registry = invariant_compliant_registry(0);
        let subnet_id = add_cloud_engine_subnet(&mut registry);

        // Step 2: Run the code under test.
        let mutation = blank_replica_version_id_mutation(&registry, subnet_id);
        registry.check_global_state_invariants(&mutation);

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't elected.")]
    fn panic_when_non_cloud_engine_subnet_has_blank_replica_version_id() {
        // Step 1: Prepare the world.

        let _restore_on_drop = temporarily_enable_blank_replica_version_id_for_cloud_engines();
        let mut registry = invariant_compliant_registry(0);

        // Like in previous tests, elect a couple of replica versions, and
        // upgrade 10% of the CloudEngine fleet to version 2 (from version 1).
        registry.maybe_apply_mutation_internal(elect_version_mutations(vec![
            REPLICA_VERSION_ID_1.to_string(),
            REPLICA_VERSION_ID_2.to_string(),
        ]));
        registry.maybe_apply_mutation_internal(vec![insert(
            make_standard_engine_replica_version_record_key().as_bytes(),
            StandardEngineReplicaVersionRecord {
                new_replica_version_id: REPLICA_VERSION_ID_2.to_string(),
                old_replica_version_id: REPLICA_VERSION_ID_1.to_string(),
                deployment_progress: 0.1,
            }
            .encode_to_vec(),
        )]);

        // Step 2: Run the code under test.

        // Blank the replica_version_id field of a (non-CloudEngine) subnet.
        let list = registry.get_subnet_list_record();
        let subnet_id =
            SubnetId::from(PrincipalId::try_from(list.subnets.first().unwrap()).unwrap());
        let mut subnet = registry.get_subnet_or_panic(subnet_id);
        assert_ne!(subnet.subnet_type, SubnetType::CloudEngine as i32);
        subnet.replica_version_id = "".to_string();

        // Update the record.
        let mutation = vec![upsert(
            make_subnet_record_key(subnet_id).into_bytes(),
            subnet.encode_to_vec(),
        )];
        registry.check_global_state_invariants(&mutation);

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't elected.")]
    fn panic_when_retiring_a_version_in_use() {
        let registry = invariant_compliant_registry(0);

        let mutation = vec![delete(
            make_replica_version_key(ReplicaVersion::default()).as_bytes(),
        )];
        registry.check_global_state_invariants(&mutation);
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't elected.")]
    fn panic_when_retiring_unassigned_nodes_version() {
        let mut registry = invariant_compliant_registry(0);

        let replica_version_id = "unassigned_version".to_string();
        let replica_version = ReplicaVersionRecord {
            release_package_sha256_hex: "".to_string(),
            release_package_urls: vec![],
            guest_launch_measurements: None,
        };
        let unassigned_nodes_config = UnassignedNodesConfigRecord {
            ssh_readonly_access: vec![],
            replica_version: replica_version_id.clone(),
        };

        let init = vec![
            insert(
                make_replica_version_key(&replica_version_id).as_bytes(),
                replica_version.encode_to_vec(),
            ),
            insert(
                make_unassigned_nodes_config_record_key(),
                unassigned_nodes_config.encode_to_vec(),
            ),
        ];
        registry.maybe_apply_mutation_internal(init);

        let mutation = vec![delete(
            make_replica_version_key(replica_version_id).as_bytes(),
        )];
        registry.check_global_state_invariants(&mutation);
    }

    #[test]
    #[should_panic(expected = "Using a version that isn't elected.")]
    fn panic_when_retiring_a_version_referenced_by_standard_engine_record() {
        // Step 1: Prepare the world.

        // Step 1.1: Elect two replica versions.
        let mut registry = invariant_compliant_registry(0);
        registry.maybe_apply_mutation_internal(elect_version_mutations(vec![
            REPLICA_VERSION_ID_1.to_string(),
            REPLICA_VERSION_ID_2.to_string(),
        ]));

        // Step 1.2: Start upgrading engines from one elected version to the
        // other.
        registry.maybe_apply_mutation_internal(vec![insert(
            make_standard_engine_replica_version_record_key(),
            StandardEngineReplicaVersionRecord {
                new_replica_version_id: REPLICA_VERSION_ID_2.to_string(),
                old_replica_version_id: REPLICA_VERSION_ID_1.to_string(),
                deployment_progress: 0.1,
            }
            .encode_to_vec(),
        )]);

        // Step 2: Run the code under test. Try to un-elect one of the versions
        // referenced by the (engine replica version) upgrade.
        let mutation = delete(make_replica_version_key(REPLICA_VERSION_ID_2).as_bytes());
        registry.check_global_state_invariants(&[mutation]);

        // Step 3: Verify result(s).
        // The assertion is at the top: #[should_panic(...)].
    }

    fn check_replica_version(hash: &str, urls: Vec<String>) {
        let registry = invariant_compliant_registry(0);

        let key = make_replica_version_key(ReplicaVersion::default());
        let value = ReplicaVersionRecord {
            release_package_sha256_hex: hash.into(),
            release_package_urls: urls,
            guest_launch_measurements: Some(GuestLaunchMeasurements {
                guest_launch_measurements: vec![GuestLaunchMeasurement {
                    measurement: vec![0x42; 48],
                    metadata: Some(GuestLaunchMeasurementMetadata {
                        kernel_cmdline: Some("foo=bar".to_string()),
                        vcpu_type: None,
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
    #[should_panic(expected = "guest_launch_measurements must not be empty")]
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
