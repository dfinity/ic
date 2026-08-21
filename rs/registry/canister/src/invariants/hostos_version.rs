use std::collections::BTreeSet;

use crate::invariants::common::{
    InvariantCheckError, RegistrySnapshot, assert_valid_urls_and_hash,
    get_all_hostos_version_records_with_keys, get_all_node_records,
};

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
    // Collect all referenced HostOS versions
    let versions_in_use = get_all_hostos_versions_of_nodes(snapshot);

    // Re-collect since we can't compare `BTreeSet<String>` with `BTreeSet<&String>` with `is_superset`.
    let versions_in_use: BTreeSet<_> = versions_in_use.iter().collect();

    // Get the current list of registered HostOS versions
    let elected_versions = get_all_hostos_version_records_with_keys(snapshot);
    let elected_set: BTreeSet<_> = elected_versions.keys().collect();
    assert!(
        elected_set.is_superset(&versions_in_use),
        "Using a version that isn't elected. Elected versions: {elected_set:?}, in use: {versions_in_use:?}."
    );
    assert!(
        elected_set.iter().all(|v| !v.trim().is_empty()),
        "Elected an empty version ID."
    );

    for (key, record) in elected_versions {
        // Check whether release package URLs (update image) and corresponding hash are well-formed.
        // As file-based URLs are only used in test-deployments, we disallow file:/// URLs.
        assert_valid_urls_and_hash(
            &record.release_package_urls,
            &record.release_package_sha256_hex,
            false,
        );

        // Enforce that the stored version always matches the key
        assert_eq!(
            record.hostos_version_id, key,
            "The registry key and internal `hostos_version_id` must be consistent."
        );
    }

    Ok(())
}

/// Returns the list of HostOS versions where each version is referred to
/// by at least one node.
fn get_all_hostos_versions_of_nodes(snapshot: &RegistrySnapshot) -> BTreeSet<String> {
    get_all_node_records(snapshot)
        .into_values()
        .filter_map(|node_record| node_record.hostos_version_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::common::test_helpers::invariant_compliant_registry;

    use ic_protobuf::registry::hostos_version::v1::HostosVersionRecord;
    use ic_registry_keys::make_hostos_version_key;
    use ic_registry_transport::upsert;
    use prost::Message;

    #[test]
    #[should_panic(
        expected = "The registry key and internal `hostos_version_id` must be consistent."
    )]
    fn panic_with_inner_version_mismatch() {
        let registry = invariant_compliant_registry(0);

        let key = make_hostos_version_key("FOO");
        let value = HostosVersionRecord {
            hostos_version_id: "BAR".to_string(),
            ..Default::default()
        }
        .encode_to_vec();

        let mutation = vec![upsert(key.as_bytes(), value)];
        registry.check_global_state_invariants(&mutation);
    }
}
