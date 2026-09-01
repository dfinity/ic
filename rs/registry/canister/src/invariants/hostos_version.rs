use std::collections::BTreeSet;

use crate::invariants::common::{
    InvariantCheckError, RegistrySnapshot, assert_valid_urls_and_hash,
    get_all_hostos_version_records, get_all_node_records,
};

use ic_types::hostos_version::HostosVersion;

/// A predicate on the HostOS version records contained in a registry
/// snapshot.
///
/// For each HostOS version that is either referred to in a NodeRecord
/// or that is contained in a HostosVersionRecord, the following is checked:
///
/// * The corresponding HostosVersionRecord exists.
/// * The version ID is well-formed, i.e. it can be parsed as a HostosVersion.
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
    let elected_versions = get_all_hostos_version_records(snapshot);
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
        // Enforce that the version ID is well-formed, so that consumers reading
        // it back out of the Registry can turn it into a HostosVersion.
        if let Err(err) = HostosVersion::try_from(key.as_str()) {
            panic!("Registered an invalid HostOS version ID: {err}");
        }

        // Check whether release package URLs (update image) and corresponding hash are well-formed.
        // As file-based URLs are only used in test-deployments, we disallow file:/// URLs.
        assert_valid_urls_and_hash(
            &record.release_package_urls,
            &record.release_package_sha256_hex,
            false,
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
    use ic_registry_transport::{insert, pb::v1::RegistryMutation};
    use prost::Message;

    // HostOS version IDs are git commit IDs (pointing to the source code used
    // to build HostOS).
    const HOSTOS_VERSION_ID: &str = "eb3ab997954f2a91db8a42f84132cf37078d481c";

    fn register_version_mutation(hostos_version_id: &str) -> Vec<RegistryMutation> {
        vec![insert(
            make_hostos_version_key(hostos_version_id).as_bytes(),
            HostosVersionRecord {
                hostos_version_id: hostos_version_id.to_string(),

                release_package_urls: vec![],
                release_package_sha256_hex: "".to_string(),
            }
            .encode_to_vec(),
        )]
    }

    #[test]
    fn no_panic_when_registering_valid_version() {
        let registry = invariant_compliant_registry(0);

        let mutations = register_version_mutation(HOSTOS_VERSION_ID);

        registry.check_global_state_invariants(&mutations);
    }

    #[test]
    #[should_panic(expected = "Registered an invalid HostOS version ID")]
    fn panic_when_registering_version_with_illegal_characters() {
        let registry = invariant_compliant_registry(0);

        let mutations = register_version_mutation("G@RBAGE");

        registry.check_global_state_invariants(&mutations);
    }
}
