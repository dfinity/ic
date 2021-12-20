use crate::invariants::common::{
    get_subnet_ids_from_snapshot, get_value_from_snapshot, InvariantCheckError, RegistrySnapshot,
};

use url::Url;

use ic_base_types::SubnetId;
use ic_nns_common::registry::decode_or_panic;
use ic_protobuf::registry::{
    replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    subnet::v1::SubnetRecord,
};
use ic_registry_keys::{
    make_blessed_replica_version_key, make_replica_version_key, make_subnet_record_key,
};

/// A predicate on the replica version records contained in a registry
/// snapshot.
///
/// For each replica version that is either referred to in an SubnetRecord
/// of a subnet that is listed in the subnet list or that is contained
/// the BlessedReplicaVersions-List, the following is checked:
///
/// * The corresponding ReplicaVersionRecord exists.
/// * At least one of either the replica, orchestrator or release package is
///   specified.
/// * Each set URL is well-formed.
/// * Each set hash is a well-formed hex-encoded SHA256 value.
pub(crate) fn check_replica_version_invariants(
    snapshot: &RegistrySnapshot,
    strict: bool,
) -> Result<(), InvariantCheckError> {
    let mut versions = get_all_replica_versions_of_subnets(snapshot);
    let blessed_version_ids = snapshot
        .get(make_blessed_replica_version_key().as_bytes())
        .map(|bytes| {
            let version_list = decode_or_panic::<BlessedReplicaVersions>(bytes.clone());
            version_list.blessed_version_ids
        })
        .unwrap_or_else(Vec::default);
    versions.extend(blessed_version_ids);
    versions.dedup();

    // Check whether release package URL (iso image) and corresponding
    // hash is well-formed. As file-based URLs are only used in
    // test-deployments, we disallow file:/// URLs.
    if strict {
        for version in versions {
            let r = get_replica_version_record(snapshot, version);

            // An entry where all URLs are unspecified is invalid.
            if r.release_package_url.is_empty() {
                return Err(InvariantCheckError {
                    msg: "release package URL must be set".to_string(),
                    source: None,
                });
            }

            assert_valid_url_and_hash(&r.release_package_url, &r.release_package_sha256_hex, false);
        }
    }

    Ok(())
}

fn get_replica_version_record(
    snapshot: &RegistrySnapshot,
    version: String,
) -> ReplicaVersionRecord {
    get_value_from_snapshot(snapshot, make_replica_version_key(version.clone()))
        .unwrap_or_else(|| panic!("Could not find replica version: {}", version))
}

fn get_subnet_record(snapshot: &RegistrySnapshot, subnet_id: SubnetId) -> SubnetRecord {
    get_value_from_snapshot(snapshot, make_subnet_record_key(subnet_id))
        .unwrap_or_else(|| panic!("Could not get subnet record for subnet: {}", subnet_id))
}

/// Returns the list of replica versions where each version is referred to
/// by at least one subnet.
fn get_all_replica_versions_of_subnets(snapshot: &RegistrySnapshot) -> Vec<String> {
    get_subnet_ids_from_snapshot(snapshot)
        .iter()
        .map(|subnet_id| get_subnet_record(snapshot, *subnet_id).replica_version_id)
        .collect()
}

fn assert_sha256(s: &str) {
    if s.len() != 64 {
        panic!(
            "Hash value should be 64 characters long. (actual len: {})",
            s.len()
        );
    }
    if s.bytes().any(|x| !x.is_ascii_hexdigit()) {
        panic!("Hash contains at least one invalid character: `{}`", s);
    }
}

fn assert_valid_url_and_hash(url: &str, hash: &str, allow_file_url: bool) {
    // Either both, the URL and the hash are set, or both are not set.
    if (url.is_empty() as i32 ^ hash.is_empty() as i32) > 0 {
        panic!("Either both, an url and a hash must be set, or none.");
    }
    if url.is_empty() {
        return;
    }

    assert_sha256(hash);
    // File URLs are used in test deployments. We only disallow non-ASCII.
    if allow_file_url && url.starts_with("file://") {
        if !url.is_ascii() {
            panic!("file-URL contains non-ASCII characters.");
        }
        return;
    }

    let _ = Url::parse(url).expect("Could not parse URL.");
}
