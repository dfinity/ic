use std::{
    collections::BTreeMap,
    convert::TryFrom,
    error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::{
    api_boundary_node::v1::ApiBoundaryNodeRecord, crypto::v1::ChainKeyEnabledSubnetList,
    hostos_version::v1::HostosVersionRecord, node::v1::NodeRecord, subnet::v1::SubnetListRecord,
};
use ic_registry_keys::{
    CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX, HOSTOS_VERSION_KEY_PREFIX, NODE_RECORD_KEY_PREFIX,
    get_api_boundary_node_record_node_id, get_node_record_node_id, make_node_record_key,
    make_subnet_list_record_key,
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

/// Returns all node records in the snapshot.
pub(crate) fn get_all_node_records(snapshot: &RegistrySnapshot) -> Vec<NodeRecord> {
    let mut nodes: Vec<NodeRecord> = Vec::new();
    for (k, v) in snapshot {
        if k.starts_with(NODE_RECORD_KEY_PREFIX.as_bytes()) {
            let record = NodeRecord::decode(v.as_slice()).unwrap();
            nodes.push(record);
        }
    }
    nodes
}

pub(crate) fn get_value_from_snapshot<T: Message + Default>(
    snapshot: &RegistrySnapshot,
    key: String,
) -> Option<T> {
    snapshot
        .get(key.as_bytes())
        .map(|v| T::decode(v.as_slice()).unwrap())
}

// Retrieve all records that serve as lists of subnets that can sign with chain keys
#[allow(dead_code)]
pub(crate) fn get_all_chain_key_signing_subnet_list_records(
    snapshot: &RegistrySnapshot,
) -> BTreeMap<String, ChainKeyEnabledSubnetList> {
    let mut result = BTreeMap::<String, ChainKeyEnabledSubnetList>::new();
    for key in snapshot.keys() {
        let signing_subnet_list_key = String::from_utf8(key.clone()).unwrap();
        if signing_subnet_list_key.starts_with(CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX) {
            let chain_key_signing_subnet_list_record = match snapshot.get(key) {
                Some(chain_key_signing_subnet_list_record) => ChainKeyEnabledSubnetList::decode(
                    chain_key_signing_subnet_list_record.as_slice(),
                )
                .unwrap(),
                None => panic!("Cannot fetch ChainKeySigningSubnetList record for an existing key"),
            };
            result.insert(
                signing_subnet_list_key,
                chain_key_signing_subnet_list_record,
            );
        }
    }
    result
}

// Retrieve all HostOS version records
pub(crate) fn get_all_hostos_version_records(
    snapshot: &RegistrySnapshot,
) -> Vec<HostosVersionRecord> {
    let mut result = Vec::new();
    for key in snapshot.keys() {
        let hostos_version_key = String::from_utf8(key.clone()).unwrap();
        if hostos_version_key.starts_with(HOSTOS_VERSION_KEY_PREFIX) {
            let hostos_version_record = match snapshot.get(key) {
                Some(hostos_version_record_bytes) => {
                    HostosVersionRecord::decode(hostos_version_record_bytes.as_slice()).unwrap()
                }
                None => panic!("Cannot fetch HostosVersionRecord for an existing key"),
            };
            result.push(hostos_version_record);
        }
    }
    result
}

/// Returns all node records from the snapshot.
pub(crate) fn get_node_records_from_snapshot(
    snapshot: &RegistrySnapshot,
) -> BTreeMap<NodeId, NodeRecord> {
    let mut result = BTreeMap::<NodeId, NodeRecord>::new();
    for key in snapshot.keys() {
        if let Some(principal_id) =
            get_node_record_node_id(String::from_utf8(key.clone()).unwrap().as_str())
        {
            // This is indeed a node record
            let node_record = match snapshot.get(key) {
                Some(node_record_bytes) => {
                    NodeRecord::decode(node_record_bytes.as_slice()).unwrap()
                }
                None => panic!("Cannot fetch node record for an existing key"),
            };
            let node_id = NodeId::from(principal_id);
            result.insert(node_id, node_record);
        }
    }
    result
}

/// Returns all api boundary node records from the snapshot.
pub(crate) fn get_api_boundary_node_records_from_snapshot(
    snapshot: &RegistrySnapshot,
) -> BTreeMap<NodeId, ApiBoundaryNodeRecord> {
    let mut result = BTreeMap::<NodeId, ApiBoundaryNodeRecord>::new();
    for (key, value) in snapshot.iter() {
        let key_str =
            String::from_utf8(key.clone()).expect("failed to convert UTF-8 byte vector to string");
        if let Some(principal_id) = get_api_boundary_node_record_node_id(&key_str) {
            // This is indeed an api boundary node record
            let api_boundary_node_record = ApiBoundaryNodeRecord::decode(value.as_slice()).unwrap();
            let node_id = NodeId::from(principal_id);
            result.insert(node_id, api_boundary_node_record);
        }
    }
    result
}

/// Returns an all api boundary node ids record from the registry snapshot.
pub(crate) fn get_api_boundary_node_ids_from_snapshot(
    snapshot: &RegistrySnapshot,
) -> Result<Vec<NodeId>, InvariantCheckError> {
    let api_bn_ids: Result<Vec<NodeId>, InvariantCheckError> = snapshot
        .keys()
        .cloned()
        .map(|key| {
            String::from_utf8(key).map_err(|_| InvariantCheckError {
                msg: "Failed to decode keys from the RegistrySnapshot".to_string(),
                source: None,
            })
        })
        .collect::<Result<Vec<String>, InvariantCheckError>>()
        .map(|keys| {
            keys.into_iter()
                .filter_map(|key_str| get_api_boundary_node_record_node_id(&key_str))
                .map(NodeId::from)
                .collect()
        });

    api_bn_ids
}

/// Returns node record from the snapshot corresponding to a key.
pub(crate) fn get_node_record_from_snapshot(
    key: NodeId,
    snapshot: &RegistrySnapshot,
) -> Result<Option<NodeRecord>, InvariantCheckError> {
    let key = make_node_record_key(key);
    let value = snapshot.get(key.as_bytes());
    value
        .map(|bytes| {
            NodeRecord::decode(bytes.as_slice()).map_err(|err| InvariantCheckError {
                msg: format!("Deserialize registry value failed with {err}"),
                source: None,
            })
        })
        .transpose()
}

pub(crate) fn get_subnet_ids_from_snapshot(snapshot: &RegistrySnapshot) -> Vec<SubnetId> {
    get_value_from_snapshot::<SubnetListRecord>(snapshot, make_subnet_list_record_key())
        .map(|r| {
            r.subnets
                .iter()
                .map(|s| SubnetId::from(PrincipalId::try_from(s.clone().as_slice()).unwrap()))
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
    #[should_panic(expected = "DecodeError")]
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
    #[should_panic(expected = "DecodeError")]
    fn test_get_value_from_snapshot_panics() {
        let mut snapshot = RegistrySnapshot::new();
        let node_id: NodeId = PrincipalId::new_node_test_id(0).into();
        let key = make_api_boundary_node_record_key(node_id);
        snapshot.insert(
            key.clone().into_bytes(), // correct key
            vec![0],                  // incorrect value, not an encoded ApiBoundaryNodeRecord
        );
        // this call should panic when decoding the ApiBoundaryNodeRecord
        get_value_from_snapshot::<ApiBoundaryNodeRecord>(&snapshot, key);
    }
}
