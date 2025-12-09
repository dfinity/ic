use super::*;
use ic_management_canister_types_private::{EcdsaCurve, SchnorrAlgorithm, SchnorrKeyId};
use rand::Rng;
use strum::IntoEnumIterator;

#[test]
fn should_parse_crypto_node_key() {
    let mut rng = rand::thread_rng();
    for key_purpose in &[
        KeyPurpose::NodeSigning,
        KeyPurpose::DkgDealingEncryption,
        KeyPurpose::CommitteeSigning,
    ] {
        let n: u64 = rng.r#gen();
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
fn ecdsa_enabled_subnet_list_bad_key_id_error_message() {
    let bad_key = "key_without_curve";
    let signing_subnet_list_key = format!("{ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX}{bad_key}");
    assert_eq!(
        get_ecdsa_key_id_from_signing_subnet_list_key(&signing_subnet_list_key).unwrap_err(),
        RegistryClientError::DecodeError {
            error: "ECDSA Signing Subnet List key id key_id_key_without_curve could not be converted to an EcdsaKeyId: \"ECDSA key id key_without_curve does not contain a ':'\"".to_string()
        }
    )
}

#[test]
fn ecdsa_enabled_subnet_list_bad_curve_error_message() {
    let bad_key = "UnknownCurve:key_name";
    let signing_subnet_list_key = format!("{ECDSA_SIGNING_SUBNET_LIST_KEY_PREFIX}{bad_key}");
    assert_eq!(
        get_ecdsa_key_id_from_signing_subnet_list_key(&signing_subnet_list_key).unwrap_err(),
        RegistryClientError::DecodeError {
            error: "ECDSA Signing Subnet List key id key_id_UnknownCurve:key_name could not be converted to an EcdsaKeyId: \"UnknownCurve is not a recognized ECDSA curve\"".to_string()
        }
    )
}

#[test]
fn chain_key_enabled_subnet_list_key_round_trips() {
    for algorithm in SchnorrAlgorithm::iter() {
        for name in ["Ed25519", "", "other_key", "other key", "other:key"] {
            let key_id = MasterPublicKeyId::Schnorr(SchnorrKeyId {
                algorithm,
                name: name.to_string(),
            });
            let enabled_subnet_list_key = make_chain_key_enabled_subnet_list_key(&key_id);
            assert_eq!(
                get_master_public_key_id_from_signing_subnet_list_key(&enabled_subnet_list_key)
                    .unwrap(),
                key_id
            );
        }
    }

    for curve in EcdsaCurve::iter() {
        for name in ["secp256k1", "", "other_key", "other key", "other:key"] {
            let key_id = MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                curve,
                name: name.to_string(),
            });
            let enabled_subnet_list_key = make_chain_key_enabled_subnet_list_key(&key_id);
            assert_eq!(
                get_master_public_key_id_from_signing_subnet_list_key(&enabled_subnet_list_key)
                    .unwrap(),
                key_id
            );
        }
    }
}

#[test]
fn chain_key_enabled_subnet_list_bad_key_id_error_message() {
    let bad_key = "key_without_curve";
    let signing_subnet_list_key =
        format!("{CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX}{bad_key}");
    assert_eq!(
        get_master_public_key_id_from_signing_subnet_list_key(&signing_subnet_list_key).unwrap_err(),
        RegistryClientError::DecodeError {
            error: "Chain Key Signing Subnet List key id master_public_key_id_key_without_curve could not be converted to a MasterPublicKeyId: \"Master public key id key_without_curve does not contain a ':'\"".to_string()
        }
    )
}

#[test]
fn chain_key_enabled_subnet_list_bad_curve_error_message() {
    let bad_key = "ecdsa:UnknownCurve:key_name";
    let signing_subnet_list_key =
        format!("{CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX}{bad_key}");
    assert_eq!(
        get_master_public_key_id_from_signing_subnet_list_key(&signing_subnet_list_key).unwrap_err(),
        RegistryClientError::DecodeError {
            error: "Chain Key Signing Subnet List key id master_public_key_id_ecdsa:UnknownCurve:key_name could not be converted to a MasterPublicKeyId: \"UnknownCurve is not a recognized ECDSA curve\"".to_string()
        }
    )
}

#[test]
fn chain_key_enabled_subnet_list_bad_scheme_error_message() {
    let bad_key = "UnknownScheme:UnknownCurve:key_name";
    let signing_subnet_list_key =
        format!("{CHAIN_KEY_ENABLED_SUBNET_LIST_KEY_PREFIX}{bad_key}");
    assert_eq!(
        get_master_public_key_id_from_signing_subnet_list_key(&signing_subnet_list_key).unwrap_err(),
        RegistryClientError::DecodeError {
            error: "Chain Key Signing Subnet List key id master_public_key_id_UnknownScheme:UnknownCurve:key_name could not be converted to a MasterPublicKeyId: \"Scheme UnknownScheme in master public key id UnknownScheme:UnknownCurve:key_name is not supported.\"".to_string()
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
        format!("{}", FirewallRulesScope::ApiBoundaryNodes),
        FIREWALL_RULES_SCOPE_API_BOUNDARY_NODES
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
        FirewallRulesScope::from_str(FIREWALL_RULES_SCOPE_API_BOUNDARY_NODES).unwrap(),
        FirewallRulesScope::ApiBoundaryNodes,
    );
    assert_eq!(
        FirewallRulesScope::from_str(
            format!("{FIREWALL_RULES_SCOPE_SUBNET_PREFIX}({id})").as_str()
        )
        .unwrap(),
        FirewallRulesScope::Subnet(SubnetId::from(id))
    );
    assert_eq!(
        FirewallRulesScope::from_str(
            format!("{FIREWALL_RULES_SCOPE_NODE_PREFIX}({id})").as_str()
        )
        .unwrap(),
        FirewallRulesScope::Node(NodeId::from(id))
    );
}
