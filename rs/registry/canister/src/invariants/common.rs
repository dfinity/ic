use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    error,
    fmt::{Display, Formatter, Result as FmtResult},
    ops::Bound::{Included, Unbounded},
};

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::{
    api_boundary_node::v1::ApiBoundaryNodeRecord, crypto::v1::ChainKeyEnabledSubnetList,
    hostos_version::v1::HostosVersionRecord, node::v1::NodeRecord,
    replica_version::v1::ReplicaVersionRecord, subnet::v1::SubnetListRecord,
};
use ic_registry_keys::{
    API_BOUNDARY_NODE_RECORD_KEY_PREFIX, CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX,
    HOSTOS_VERSION_KEY_PREFIX, NODE_RECORD_KEY_PREFIX, REPLICA_VERSION_KEY_PREFIX,
    make_node_record_key, make_subnet_list_record_key,
};
use prost::Message;
use url::Url;

/// A representation of the data held by the registry.
/// It is kept in-memory only, for global consistency checks before mutations
/// are finalized.
pub(crate) type RegistrySnapshot = BTreeMap<Vec<u8>, Vec<u8>>;

#[derive(Debug)]
pub(crate) struct InvariantCheckError {
    pub msg: String,
    pub source: Option<Box<dyn error::Error + 'static>>,
}

impl Display for InvariantCheckError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match &self.source {
            Some(source) => write!(f, "InvariantCheckError: {}, cause: {}", self.msg, source),
            None => write!(f, "InvariantCheckError: {}", self.msg),
        }
    }
}

// TODO(NNS1-488) Improved error handling
impl error::Error for InvariantCheckError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

fn registry_snapshot_range<T: Message + Default>(
    snapshot: &RegistrySnapshot,
    prefix: &str,
) -> Result<BTreeMap<String, T>, InvariantCheckError> {
    let mut nodes = BTreeMap::new();

    // Note: effectively .range(PREFIX..)
    for (k, v) in snapshot.range::<[u8], _>((Included(prefix.as_bytes()), Unbounded)) {
        let Some(k) = k.strip_prefix(prefix.as_bytes()) else {
            break;
        };

        let key = str::from_utf8(k)
            .map_err(|err| InvariantCheckError {
                msg: format!("Failed to decode keys from the RegistrySnapshot: {err}"),
                source: None,
            })?
            .to_string();
        let value = T::decode(v.as_slice()).map_err(|err| InvariantCheckError {
            msg: format!("Deserialize registry value for key '{key}' failed with {err}"),
            source: None,
        })?;

        nodes.insert(key, value);
    }

    Ok(nodes)
}

/// Returns all node records in the snapshot.
pub(crate) fn get_all_node_records(snapshot: &RegistrySnapshot) -> BTreeMap<NodeId, NodeRecord> {
    registry_snapshot_range::<NodeRecord>(snapshot, NODE_RECORD_KEY_PREFIX)
        .unwrap()
        .into_iter()
        .map(|(k, v)| (NodeId::from(k.parse::<PrincipalId>().unwrap()), v))
        .collect()
}

/// Returns all replica version records in the snapshot.
pub(crate) fn get_all_replica_version_records(
    snapshot: &RegistrySnapshot,
) -> BTreeMap<String, ReplicaVersionRecord> {
    registry_snapshot_range::<ReplicaVersionRecord>(snapshot, REPLICA_VERSION_KEY_PREFIX).unwrap()
}

// Retrieve all records that serve as lists of subnets that can sign with chain keys
pub(crate) fn get_all_chain_key_signing_subnet_list_records(
    snapshot: &RegistrySnapshot,
) -> BTreeMap<String, ChainKeyEnabledSubnetList> {
    registry_snapshot_range::<ChainKeyEnabledSubnetList>(
        snapshot,
        CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX,
    )
    .unwrap()
    // TODO: Cleanup downstream users, and remove this workaround.
    .into_iter()
    // Preserve the prefix for crypto code, which depends on it downstream.
    .map(|(k, v)| (format!("{CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX}{k}"), v))
    .collect()
}

// Retrieve all HostOS version records
pub(crate) fn get_all_hostos_version_records(
    snapshot: &RegistrySnapshot,
) -> BTreeMap<String, HostosVersionRecord> {
    registry_snapshot_range::<HostosVersionRecord>(snapshot, HOSTOS_VERSION_KEY_PREFIX).unwrap()
}

/// Returns all api boundary node records from the snapshot.
pub(crate) fn get_api_boundary_node_records_from_snapshot(
    snapshot: &RegistrySnapshot,
) -> BTreeMap<NodeId, ApiBoundaryNodeRecord> {
    registry_snapshot_range::<ApiBoundaryNodeRecord>(snapshot, API_BOUNDARY_NODE_RECORD_KEY_PREFIX)
        .unwrap()
        .into_iter()
        .map(|(k, v)| (NodeId::from(k.parse::<PrincipalId>().unwrap()), v))
        .collect()
}

pub(crate) fn get_value_from_snapshot<T: Message + Default>(
    snapshot: &RegistrySnapshot,
    key: &str,
) -> Result<Option<T>, InvariantCheckError> {
    snapshot
        .get(key.as_bytes())
        .map(|v| {
            T::decode(v.as_slice()).map_err(|err| InvariantCheckError {
                msg: format!("Deserialize registry value for key '{key}' failed with {err}"),
                source: None,
            })
        })
        .transpose()
}

/// Returns node record from the snapshot corresponding to a key.
pub(crate) fn get_node_record_from_snapshot(
    key: NodeId,
    snapshot: &RegistrySnapshot,
) -> Result<Option<NodeRecord>, InvariantCheckError> {
    get_value_from_snapshot::<NodeRecord>(snapshot, &make_node_record_key(key))
}

pub(crate) fn get_subnet_ids_from_snapshot(snapshot: &RegistrySnapshot) -> BTreeSet<SubnetId> {
    get_value_from_snapshot::<SubnetListRecord>(snapshot, &make_subnet_list_record_key())
        .unwrap()
        .map(|r| {
            r.subnets
                .iter()
                .map(|s| SubnetId::from(PrincipalId::try_from(s).unwrap()))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn assert_sha256(s: &str) {
    if s.bytes().any(|x| !x.is_ascii_hexdigit()) {
        panic!("Hash contains at least one invalid character: `{s}`");
    }

    if s.len() != 64 {
        panic!("Hash is an invalid length: `{s}`");
    }
}

pub(crate) fn assert_valid_urls_and_hash(urls: &[String], hash: &str, allow_file_url: bool) {
    // Either both, the URL and the hash are set, or both are not set.
    if (urls.is_empty() as i32 ^ hash.is_empty() as i32) > 0 {
        panic!("Either both, an url and a hash must be set, or none.");
    }
    if urls.is_empty() {
        return;
    }

    assert_sha256(hash);

    urls.iter().for_each(|url|
        // File URLs are used in test deployments. We only disallow non-ASCII.
        if allow_file_url && url.starts_with("file://") {
            assert!(url.is_ascii(), "file-URL {url} contains non-ASCII characters.");
        }
        // if it's not a file URL, it should be a valid URL.
        else if let Err(e) = Url::parse(url) {
            panic!("Release package URL {url} is not valid: {e}");
        }
    );
}

#[cfg(test)]
mod tests {
    use ic_base_types::{NodeId, PrincipalId};
    use ic_protobuf::registry::api_boundary_node::v1::ApiBoundaryNodeRecord;
    use ic_registry_keys::make_api_boundary_node_record_key;
    use prost::Message;

    use super::{
        RegistrySnapshot, get_api_boundary_node_records_from_snapshot, get_value_from_snapshot,
    };

    #[test]
    fn test_get_api_boundary_node_records_from_snapshot_success() {
        let mut snapshot = RegistrySnapshot::new();
        let node_id: NodeId = PrincipalId::new_node_test_id(0).into();
        let record = ApiBoundaryNodeRecord::default();
        snapshot.insert(
            make_api_boundary_node_record_key(node_id).into_bytes(), // correct key
            record.encode_to_vec(),                                  // correct value
        );

        let api_bn_records = get_api_boundary_node_records_from_snapshot(&snapshot);
        assert_eq!(api_bn_records.len(), 1);
        assert_eq!(api_bn_records[&node_id], record);
    }

    #[test]
    #[should_panic(expected = "failed to decode")]
    fn test_get_api_boundary_node_records_from_snapshot_with_wrongly_encoded_record() {
        let mut snapshot = RegistrySnapshot::new();
        let node_id: NodeId = PrincipalId::new_node_test_id(0).into();
        snapshot.insert(
            make_api_boundary_node_record_key(node_id).into_bytes(), // correct key
            vec![0], // incorrect value, not an encoded ApiBoundaryNodeRecord
        );
        // this call should panic when decoding the ApiBoundaryNodeRecord
        get_api_boundary_node_records_from_snapshot(&snapshot);
    }

    #[test]
    #[should_panic(expected = "failed to decode")]
    fn test_get_value_from_snapshot_panics() {
        let mut snapshot = RegistrySnapshot::new();
        let node_id: NodeId = PrincipalId::new_node_test_id(0).into();
        let key = make_api_boundary_node_record_key(node_id);
        snapshot.insert(
            key.clone().into_bytes(), // correct key
            vec![0],                  // incorrect value, not an encoded ApiBoundaryNodeRecord
        );
        // this call should panic when decoding the ApiBoundaryNodeRecord
        get_value_from_snapshot::<ApiBoundaryNodeRecord>(&snapshot, &key).unwrap();
    }
}
