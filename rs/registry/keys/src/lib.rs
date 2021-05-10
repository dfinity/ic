//! Functions that create keys for the registry
//!
//! Since registry mutations come from various NNS canisters, this library MUST
//! be compilable to WASM as well a native.

use ic_base_types::{NodeId, SubnetId};
use ic_types::crypto::KeyPurpose;
use ic_types::PrincipalId;
use std::str::FromStr;

pub const SUBNET_LIST_KEY: &str = "subnet_list";
/// The subnet id of the NNS subnet.
/// Remark: This subnet id actually points to the root subnet. In all cases, so
/// far, the root subnet happens to host the NNS canisters and the registry in
/// particular.
pub const ROOT_SUBNET_ID_KEY: &str = "nns_subnet_id";
pub const XDR_PER_ICP_KEY: &str = "xdr_per_icp";

pub const NODE_RECORD_KEY_PREFIX: &str = "node_record_";
pub const NODE_OPERATOR_RECORD_KEY_PREFIX: &str = "node_operator_record_";
pub const REPLICA_VERSION_KEY_PREFIX: &str = "replica_version_";
pub const SUBNET_RECORD_KEY_PREFIX: &str = "subnet_record_";
pub const CRYPTO_RECORD_KEY_PREFIX: &str = "crypto_record_";
pub const CRYPTO_TLS_CERT_KEY_PREFIX: &str = "crypto_tls_cert_";
pub const CRYPTO_THRESHOLD_SIGNING_KEY_PREFIX: &str = "crypto_threshold_signing_public_key_";

/// Returns the only key whose payload is the ICP/XDR conversion rate.
pub fn make_icp_xdr_conversion_rate_record_key() -> String {
    XDR_PER_ICP_KEY.to_string()
}

/// Returns the only key whose payload is the list of subnets.
pub fn make_subnet_list_record_key() -> String {
    SUBNET_LIST_KEY.to_string()
}

/// Makes a key for a ReplicaVersion registry entry.
pub fn make_replica_version_key<S: AsRef<str>>(replica_version_id: S) -> String {
    format!(
        "{}{}",
        REPLICA_VERSION_KEY_PREFIX,
        replica_version_id.as_ref()
    )
}

/// Returns the only key whose payload is the list of blessed replica versions.
pub fn make_blessed_replica_version_key() -> String {
    "blessed_replica_versions".to_string()
}

pub fn make_routing_table_record_key() -> String {
    "routing_table".to_string()
}

pub fn make_firewall_config_record_key() -> String {
    "firewall_config".to_string()
}

pub fn make_provisional_whitelist_record_key() -> String {
    "provisional_whitelist".to_string()
}

// Makes a key for a NodeOperatorRecord.
pub fn make_node_operator_record_key(node_operator_principal_id: PrincipalId) -> String {
    format!(
        "{}{}",
        NODE_OPERATOR_RECORD_KEY_PREFIX, node_operator_principal_id
    )
}

pub fn principal_id_to_u64(principal_id: PrincipalId) -> u64 {
    let vec = principal_id.into_vec();
    let mut arr: [u8; 8] = [0; 8];
    arr.copy_from_slice(&vec[..8]);
    u64::from_le_bytes(arr)
}

/// Makes a key for a TLS certificate registry entry for a node.
pub fn make_crypto_tls_cert_key(node_id: NodeId) -> String {
    format!("{}{}", CRYPTO_TLS_CERT_KEY_PREFIX, node_id.get())
}

// If `key` starts with `CRYPTO_TLS_CERT_KEY_PREFIX`, tries to parse it to get
// NodeId. If parsing is successful, returns Some(node_id), otherwise returns
// None.
pub fn maybe_parse_crypto_tls_cert_key(key: &str) -> Option<NodeId> {
    if key.starts_with(CRYPTO_TLS_CERT_KEY_PREFIX) {
        PrincipalId::from_str(&key[CRYPTO_TLS_CERT_KEY_PREFIX.len()..])
            .map_or(None, |id| Some(NodeId::new(id)))
    } else {
        None
    }
}

/// Makes a key for a NodeRecord registry entry.
pub fn make_node_record_key(node_id: NodeId) -> String {
    format!("{}{}", NODE_RECORD_KEY_PREFIX, node_id.get())
}

/// Checks whether a given key is a node record key
pub fn is_node_record_key(key: &str) -> bool {
    key.starts_with(NODE_RECORD_KEY_PREFIX)
}

/// Returns the node_id associated with a given node_record key if
/// the key is, in fact, a valid node_record_key.
pub fn get_node_record_node_id(key: &str) -> Option<PrincipalId> {
    if key.starts_with(NODE_RECORD_KEY_PREFIX) {
        PrincipalId::from_str(&key[NODE_RECORD_KEY_PREFIX.len()..]).ok()
    } else {
        None
    }
}

/// Makes a key for a threshold signature public key entry for a subnet.
pub fn make_crypto_threshold_signing_pubkey_key(subnet_id: SubnetId) -> String {
    format!("{}{}", CRYPTO_THRESHOLD_SIGNING_KEY_PREFIX, subnet_id)
}

// If `key` starts with `CRYPTO_THRESHOLD_SIGNING_KEY_PREFIX`, tries to parse it
// to get SubnetId. If parsing is successful, returns Some(subnet_id), otherwise
// returns None.
pub fn maybe_parse_crypto_threshold_signing_pubkey_key(key: &str) -> Option<SubnetId> {
    if key.starts_with(CRYPTO_THRESHOLD_SIGNING_KEY_PREFIX) {
        PrincipalId::from_str(&key[CRYPTO_THRESHOLD_SIGNING_KEY_PREFIX.len()..])
            .map_or(None, |id| Some(SubnetId::new(id)))
    } else {
        None
    }
}

/// Makes a key for a record for the catch up package contents.
pub fn make_catch_up_package_contents_key(subnet_id: SubnetId) -> String {
    format!("catch_up_package_contents_{}", subnet_id)
}

/// Makes a key for a SubnetRecord registry entry.
pub fn make_subnet_record_key(subnet_id: SubnetId) -> String {
    format!("{}{}", SUBNET_RECORD_KEY_PREFIX, subnet_id)
}

/// Makes a key for a crypto key registry entry for a node.
pub fn make_crypto_node_key(node_id: NodeId, key_purpose: KeyPurpose) -> String {
    format!(
        "{}{}_{}",
        CRYPTO_RECORD_KEY_PREFIX,
        node_id.get(),
        key_purpose as usize
    )
}

// If `key` starts with `CRYPTO_RECORD_KEY_PREFIX`, tries to parse it to get
// NodeId and KeyPurpose. If parsing is successful, returns Some((node_id,
// key_purpose)), otherwise returns None.
pub fn maybe_parse_crypto_node_key(key: &str) -> Option<(NodeId, KeyPurpose)> {
    if key.starts_with(CRYPTO_RECORD_KEY_PREFIX) {
        let parts: Vec<&str> = key[CRYPTO_RECORD_KEY_PREFIX.len()..].split('_').collect();
        if parts.len() != 2 {
            return None;
        }
        let maybe_node_id =
            PrincipalId::from_str(parts[0]).map_or(None, |id| Some(NodeId::new(id)));
        let maybe_key_purpose = parts[1]
            .parse::<usize>()
            .map_or(None, |kp| Some(KeyPurpose::from(kp)));
        match (maybe_node_id, maybe_key_purpose) {
            (Some(id), Some(kp)) => Some((id, kp)),
            _ => None,
        }
    } else {
        None
    }
}

/// Returns the unique key that stores the information about post-genesis NNS
/// canisters.
pub fn make_nns_canister_records_key() -> String {
    "nns_canister_records".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn should_parse_crypto_node_key() {
        let mut rng = rand::thread_rng();
        for key_purpose in &[
            KeyPurpose::NodeSigning,
            KeyPurpose::DkgDealingEncryption,
            KeyPurpose::CommitteeSigning,
        ] {
            let n: u64 = rng.gen();
            let node_id = NodeId::from(PrincipalId::new_node_test_id(n));
            let crypto_node_key = make_crypto_node_key(node_id, *key_purpose);
            let parsed = maybe_parse_crypto_node_key(&crypto_node_key);
            assert!(parsed.is_some());
            let (id, kp) = parsed.unwrap();
            assert_eq!(id, node_id);
            assert_eq!(kp, *key_purpose);
        }
    }

    #[test]
    fn should_fail_parsing_crypto_node_key() {
        let node_id = NodeId::from(PrincipalId::new_node_test_id(42));
        let wrong_key = make_crypto_tls_cert_key(node_id);
        let parsed = maybe_parse_crypto_node_key(&wrong_key);
        assert!(parsed.is_none());
    }

    #[test]
    fn should_parse_crypto_tls_cert_key() {
        let node_id = NodeId::from(PrincipalId::new_node_test_id(42));
        let crypto_tls_cert_key = make_crypto_tls_cert_key(node_id);
        let parsed = maybe_parse_crypto_tls_cert_key(&crypto_tls_cert_key);
        assert!(parsed.is_some());
        let id = parsed.unwrap();
        assert_eq!(id, node_id);
    }

    #[test]
    fn should_fail_parsing_crypto_tls_cert_key() {
        let node_id = NodeId::from(PrincipalId::new_node_test_id(42));
        let wrong_key = make_crypto_node_key(node_id, KeyPurpose::NodeSigning);
        let parsed = maybe_parse_crypto_tls_cert_key(&wrong_key);
        assert!(parsed.is_none());
    }

    #[test]
    fn should_parse_crypto_threshold_signining_pubkey_key() {
        let subnet_id = SubnetId::from(PrincipalId::new_node_test_id(42));
        let threshold_signing_pk_key = make_crypto_threshold_signing_pubkey_key(subnet_id);
        let parsed = maybe_parse_crypto_threshold_signing_pubkey_key(&threshold_signing_pk_key);
        assert!(parsed.is_some());
        let id = parsed.unwrap();
        assert_eq!(id, subnet_id);
    }

    #[test]
    fn should_fail_parsing_crypto_threshold_signining_pubkey_key() {
        let node_id = NodeId::from(PrincipalId::new_node_test_id(42));
        let wrong_key = make_crypto_tls_cert_key(node_id);
        let parsed = maybe_parse_crypto_threshold_signing_pubkey_key(&wrong_key);
        assert!(parsed.is_none());
    }
}
