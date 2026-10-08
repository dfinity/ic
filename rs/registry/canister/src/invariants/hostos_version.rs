use crate::invariants::common::{
    InvariantCheckError, RegistrySnapshot, assert_valid_urls_and_hash,
    get_all_hostos_version_records, get_all_node_records, get_value_from_snapshot,
};

use ic_protobuf::registry::hostos_version::v1::HostosVersionRecord;
use ic_registry_keys::make_hostos_version_key;
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
    let mut all_versions = Vec::new();

    // Collect all referenced HostOS versions
    let node_versions = get_all_hostos_versions_of_nodes(snapshot);
    all_versions.extend(node_versions);

    // Get the current list of registered HostOS versions
    let registered_versions = get_all_hostos_version_records(snapshot);

    all_versions.extend(registered_versions.into_iter().map(|v| v.hostos_version_id));
    all_versions.dedup();

    for version in all_versions {
        // Enforce that the version ID is well-formed, so that consumers reading
        // it back out of the Registry can turn it into a HostosVersion.
        if let Err(err) = HostosVersion::try_from(version.as_str()) {
            panic!("Registered an invalid HostOS version ID: {err}");
        }

        // Check that every referenced version exists, i.e. we can only set a
        // Node's version to one that has already been added to the registry.
        let r = get_hostos_version_record(snapshot, version);

        // Check whether release package URLs (update image) and corresponding hash are well-formed.
        // As file-based URLs are only used in test-deployments, we disallow file:/// URLs.
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
    get_all_node_records(snapshot)
        .into_values()
        .filter_map(|node_record| node_record.hostos_version_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::common::test_helpers::invariant_compliant_registry;
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
