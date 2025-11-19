use crate::invariants::common::{
    InvariantCheckError, RegistrySnapshot, assert_valid_urls_and_hash,
    get_all_hostos_version_records, get_node_records_from_snapshot, get_value_from_snapshot,
};

use ic_protobuf::registry::hostos_version::v1::HostosVersionRecord;
use ic_registry_keys::make_hostos_version_key;

/// A predicate on the HostOS version records contained in a registry
/// snapshot.
///
/// For each HostOS version that is either referred to in a NodeRecord
/// or that is contained in a HostosVersionRecord, the following is checked:
///
/// * The corresponding HostosVersionRecord exists.
/// * Each set URL is well-formed.
/// * Each set hash is a well-formed hex-encoded SHA256 value.
pub(crate) fn check_hostos_version_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let mut all_versions = Vec::new();

    // Collect all referenced HostOS versions
    let node_versions = get_all_hostos_versions_of_nodes(snapshot);
    all_versions.extend(node_versions);

    // Get the current list of registered HostOS versions
    let registered_versions = get_all_hostos_version_records(snapshot);

    all_versions.extend(registered_versions.into_iter().map(|v| v.hostos_version_id));
    all_versions.dedup();

    for version in all_versions {
        // Check that every referenced version exists, i.e. we can only set a
        // Node's version to one that has already been added to the registry.
        let r = get_hostos_version_record(snapshot, version);

        // Check whether release package URL (iso image) and corresponding hash
        // are well-formed. As file-based URLs are only used in
        // test-deployments, we disallow file:/// URLs.
        assert_valid_urls_and_hash(
            &r.release_package_urls,
            &r.release_package_sha256_hex,
            false,
        );
    }

    Ok(())
}

fn get_hostos_version_record(snapshot: &RegistrySnapshot, version: String) -> HostosVersionRecord {
    get_value_from_snapshot(snapshot, make_hostos_version_key(version.clone()))
        .unwrap_or_else(|| panic!("Could not find HostOS version: {version}"))
}

/// Returns the list of HostOS versions where each version is referred to
/// by at least one node.
fn get_all_hostos_versions_of_nodes(snapshot: &RegistrySnapshot) -> Vec<String> {
    get_node_records_from_snapshot(snapshot)
        .values()
        .filter_map(|node_record| node_record.hostos_version_id.clone())
        .collect()
}
