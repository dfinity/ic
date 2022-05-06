//! Functions that create keys for the registry
//!
//! Since registry mutations come from various NNS canisters, this library MUST
//! be compilable to WASM as well a native.

use candid::{CandidType, Deserialize};
use core::fmt;
use ic_base_types::{NodeId, SubnetId};
use ic_ic00_types::EcdsaKeyId;
use ic_types::crypto::KeyPurpose;
use ic_types::registry::RegistryClientError;
use ic_types::PrincipalId;
use serde::Serialize;
use std::str::FromStr;

const SUBNET_LIST_KEY: &str = "subnet_list";
/// The subnet id of the NNS subnet.
/// Remark: This subnet id actually points to the root subnet. In all cases, so
/// far, the root subnet happens to host the NNS canisters and the registry in
/// particular.
pub const ROOT_SUBNET_ID_KEY: &str = "nns_subnet_id";
pub const NODE_REWARDS_TABLE_KEY: &str = "node_rewards_table";
const UNASSIGNED_NODES_CONFIG_RECORD_KEY: &str = "unassigned_nodes_config";

pub const NODE_RECORD_KEY_PREFIX: &str = "node_record_";
pub const NODE_OPERATOR_RECORD_KEY_PREFIX: &str = "node_operator_record_";
pub const REPLICA_VERSION_KEY_PREFIX: &str = "replica_version_";
pub const SUBNET_RECORD_KEY_PREFIX: &str = "subnet_record_";
pub const CRYPTO_RECORD_KEY_PREFIX: &str = "crypto_record_";
pub const CRYPTO_TLS_CERT_KEY_PREFIX: &str = "crypto_tls_cert_";
pub const CRYPTO_THRESHOLD_SIGNING_KEY_PREFIX: &str = "crypto_threshold_signing_public_key_";
pub const DATA_CENTER_KEY_PREFIX: &str = "data_center_record_";
pub const ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX: &str = "key_id_";

pub fn make_ecdsa_signing_subnet_list_key(key_id: &EcdsaKeyId) -> String {
    format!("{}{}", ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX, key_id)
}

pub fn get_ecdsa_key_id_from_signing_subnet_list_key(
    signing_subnet_list_key: &str,
) -> Result<EcdsaKeyId, RegistryClientError> {
    let prefix_removed = signing_subnet_list_key
        .strip_prefix(ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX)
        .ok_or_else(|| RegistryClientError::DecodeError {
            error: format!(
                "ECDSA Signing Subnet List key id {} does not start with prefix {}",
                signing_subnet_list_key, ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX
            ),
        })?;
    prefix_removed
        .parse::<EcdsaKeyId>()
        .map_err(|error| RegistryClientError::DecodeError {
            error: format!(
                "ECDSA Signing Subnet List key id {} could not be converted to an EcdsaKeyId: {:?}",
                signing_subnet_list_key, error
            ),
        })
}

/// Returns the only key whose payload is the list of subnets.
pub fn make_subnet_list_record_key() -> String {
    SUBNET_LIST_KEY.to_string()
}

pub fn make_unassigned_nodes_config_record_key() -> String {
    UNASSIGNED_NODES_CONFIG_RECORD_KEY.to_string()
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

pub fn make_canister_migrations_record_key() -> String {
    "canister_migrations".to_string()
}

// TODO: Remove when all subnets are upgraded with IC-1026
pub fn make_firewall_config_record_key() -> String {
    "firewall_config".to_string()
}

const FIREWALL_RULES_RECORD_KEY_PREFIX: &str = "firewall_rules_";
const FIREWALL_RULES_SCOPE_GLOBAL: &str = "global";
const FIREWALL_RULES_SCOPE_REPLICA_NODES: &str = "replica_nodes";
const FIREWALL_RULES_SCOPE_SUBNET_PREFIX: &str = "subnet";
const FIREWALL_RULES_SCOPE_NODE_PREFIX: &str = "node";

/// The scope for a firewall ruleset
#[derive(CandidType, Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum FirewallRulesScope {
    Node(NodeId),
    Subnet(SubnetId),
    ReplicaNodes,
    Global,
}

impl fmt::Display for FirewallRulesScope {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            FirewallRulesScope::Node(node_id) => write!(
                fmt,
                "{}_{}",
                FIREWALL_RULES_SCOPE_NODE_PREFIX,
                node_id.get()
            )?,
            FirewallRulesScope::Subnet(subnet_id) => write!(
                fmt,
                "{}_{}",
                FIREWALL_RULES_SCOPE_SUBNET_PREFIX,
                subnet_id.get()
            )?,
            FirewallRulesScope::ReplicaNodes => {
                write!(fmt, "{}", FIREWALL_RULES_SCOPE_REPLICA_NODES)?
            }
            FirewallRulesScope::Global => write!(fmt, "{}", FIREWALL_RULES_SCOPE_GLOBAL)?,
        };
        Ok(())
    }
}

impl FromStr for FirewallRulesScope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split(&['(', ')']).filter(|s| !s.is_empty()).collect();
        if parts.is_empty() || parts.len() > 2 {
            return Err("Invalid scope".to_string());
        }
        match parts[0].to_lowercase().as_str() {
            FIREWALL_RULES_SCOPE_GLOBAL => Ok(FirewallRulesScope::Global),
            FIREWALL_RULES_SCOPE_REPLICA_NODES => Ok(FirewallRulesScope::ReplicaNodes),
            FIREWALL_RULES_SCOPE_SUBNET_PREFIX => Ok(FirewallRulesScope::Subnet(SubnetId::from(
                PrincipalId::from_str(parts[1]).unwrap(),
            ))),
            FIREWALL_RULES_SCOPE_NODE_PREFIX => Ok(FirewallRulesScope::Node(NodeId::from(
                PrincipalId::from_str(parts[1]).unwrap(),
            ))),
            _ => Err("Invalid scope type".to_string()),
        }
    }
}

pub fn make_firewall_rules_record_key(scope: &FirewallRulesScope) -> String {
    format!("{}{}", FIREWALL_RULES_RECORD_KEY_PREFIX, scope)
}

/// Returns the principal_id associated with a given firewall_record key if
/// the key is, in fact, a valid firewall_record_key of node or subnet scope.
pub fn get_firewall_rules_record_principal_id(key: &str) -> Option<PrincipalId> {
    let firewall_node_record_prefix = format!(
        "{}{}_",
        FIREWALL_RULES_RECORD_KEY_PREFIX, FIREWALL_RULES_SCOPE_NODE_PREFIX
    );
    let firewall_subnet_record_prefix = format!(
        "{}{}_",
        FIREWALL_RULES_RECORD_KEY_PREFIX, FIREWALL_RULES_SCOPE_SUBNET_PREFIX
    );
    if let Some(key) = key.strip_prefix(&firewall_node_record_prefix) {
        PrincipalId::from_str(key).ok()
    } else if let Some(key) = key.strip_prefix(&firewall_subnet_record_prefix) {
        PrincipalId::from_str(key).ok()
    } else {
        None
    }
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

/// Makes a key for a TLS certificate registry entry for a node.
pub fn make_crypto_tls_cert_key(node_id: NodeId) -> String {
    format!("{}{}", CRYPTO_TLS_CERT_KEY_PREFIX, node_id.get())
}

// If `key` starts with `CRYPTO_TLS_CERT_KEY_PREFIX`, tries to parse it to get
// NodeId. If parsing is successful, returns Some(node_id), otherwise returns
// None.
pub fn maybe_parse_crypto_tls_cert_key(key: &str) -> Option<NodeId> {
    if let Some(key) = key.strip_prefix(CRYPTO_TLS_CERT_KEY_PREFIX) {
        PrincipalId::from_str(key).map_or(None, |id| Some(NodeId::new(id)))
    } else {
        None
    }
}

/// Makes a key for a NodeRecord registry entry.
pub fn make_node_record_key(node_id: NodeId) -> String {
    format!("{}{}", NODE_RECORD_KEY_PREFIX, node_id.get())
}

/// Makes a key for a DataCenterRecord registry entry.
pub fn make_data_center_record_key(dc_id: &str) -> String {
    format!("{}{}", DATA_CENTER_KEY_PREFIX, dc_id)
}

/// Checks whether a given key is a node record key
pub fn is_node_record_key(key: &str) -> bool {
    key.starts_with(NODE_RECORD_KEY_PREFIX)
}

/// Returns the node_id associated with a given node_record key if
/// the key is, in fact, a valid node_record_key.
pub fn get_node_record_node_id(key: &str) -> Option<PrincipalId> {
    if let Some(key) = key.strip_prefix(NODE_RECORD_KEY_PREFIX) {
        PrincipalId::from_str(key).ok()
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
    if let Some(key) = key.strip_prefix(CRYPTO_THRESHOLD_SIGNING_KEY_PREFIX) {
        PrincipalId::from_str(key).map_or(None, |id| Some(SubnetId::new(id)))
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
    if let Some(key) = key.strip_prefix(CRYPTO_RECORD_KEY_PREFIX) {
        let parts: Vec<&str> = key.split('_').collect();
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
    use ic_ic00_types::EcdsaCurve;
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

    #[test]
    fn escdsa_signing_subnet_list_key_round_trips() {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "some_key".to_string(),
        };
        let signing_subnet_list_key = make_ecdsa_signing_subnet_list_key(&key_id);
        assert_eq!(
            get_ecdsa_key_id_from_signing_subnet_list_key(&signing_subnet_list_key).unwrap(),
            key_id
        );
    }

    #[test]
    fn escdsa_signing_subnet_list_bad_key_id_error_message() {
        let bad_key = "key_without_curve";
        let signing_subnet_list_key =
            format!("{}{}", ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX, bad_key);
        assert_eq!(
            get_ecdsa_key_id_from_signing_subnet_list_key(&signing_subnet_list_key).unwrap_err(),
            RegistryClientError::DecodeError {
                error: "ECDSA Signing Subnet List key id key_id_key_without_curve could not be converted to an EcdsaKeyId: \"ECDSA key id key_without_curve does not contain a ':'\"".to_string()
            }
        )
    }

    #[test]
    fn escdsa_signing_subnet_list_bad_curve_error_message() {
        let bad_key = "UnknownCurve:key_name";
        let signing_subnet_list_key =
            format!("{}{}", ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX, bad_key);
        assert_eq!(
            get_ecdsa_key_id_from_signing_subnet_list_key(&signing_subnet_list_key).unwrap_err(),
            RegistryClientError::DecodeError {
                error: "ECDSA Signing Subnet List key id key_id_UnknownCurve:key_name could not be converted to an EcdsaKeyId: \"UnknownCurve is not a recognized ECDSA curve\"".to_string()
            }
        )
    }

    #[test]
    fn firewall_scope_parsing() {
        let id = PrincipalId::new_node_test_id(42);
        assert_eq!(
            format!("{}", FirewallRulesScope::Global),
            FIREWALL_RULES_SCOPE_GLOBAL
        );
        assert_eq!(
            format!("{}", FirewallRulesScope::ReplicaNodes),
            FIREWALL_RULES_SCOPE_REPLICA_NODES
        );
        assert_eq!(
            format!("{}", FirewallRulesScope::Subnet(SubnetId::from(id))),
            format!("{}_{}", FIREWALL_RULES_SCOPE_SUBNET_PREFIX, id)
        );
        assert_eq!(
            format!("{}", FirewallRulesScope::Node(NodeId::from(id))),
            format!("{}_{}", FIREWALL_RULES_SCOPE_NODE_PREFIX, id)
        );

        assert_eq!(
            FirewallRulesScope::from_str(FIREWALL_RULES_SCOPE_GLOBAL).unwrap(),
            FirewallRulesScope::Global
        );
        assert_eq!(
            FirewallRulesScope::from_str(FIREWALL_RULES_SCOPE_REPLICA_NODES).unwrap(),
            FirewallRulesScope::ReplicaNodes
        );
        assert_eq!(
            FirewallRulesScope::from_str(
                format!("{}({})", FIREWALL_RULES_SCOPE_SUBNET_PREFIX, id).as_str()
            )
            .unwrap(),
            FirewallRulesScope::Subnet(SubnetId::from(id))
        );
        assert_eq!(
            FirewallRulesScope::from_str(
                format!("{}({})", FIREWALL_RULES_SCOPE_NODE_PREFIX, id).as_str()
            )
            .unwrap(),
            FirewallRulesScope::Node(NodeId::from(id))
        );
    }
}
