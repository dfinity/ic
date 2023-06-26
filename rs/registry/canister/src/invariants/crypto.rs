use crate::common::LOG_PREFIX;
use crate::invariants::{
    common::{
        get_all_ecdsa_signing_subnet_list_records, get_node_records_from_snapshot,
        InvariantCheckError, RegistrySnapshot,
    },
    subnet::get_subnet_records_map,
};
use ic_base_types::{subnet_id_try_from_protobuf, NodeId};
use ic_protobuf::registry::crypto::v1::{PublicKey, X509PublicKeyCert};
use ic_registry_keys::{
    get_ecdsa_key_id_from_signing_subnet_list_key, make_node_record_key, make_subnet_record_key,
    maybe_parse_crypto_node_key, maybe_parse_crypto_tls_cert_key, CRYPTO_RECORD_KEY_PREFIX,
    CRYPTO_TLS_CERT_KEY_PREFIX, NODE_RECORD_KEY_PREFIX,
};
use ic_types::crypto::KeyPurpose;
use prost::Message;
use std::collections::{BTreeMap, HashMap, HashSet};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_crypto_utils_basic_sig::conversions::derive_node_id;

// All crypto public keys found for the nodes or for the subnets in the
// registry.
type AllPublicKeys = BTreeMap<(NodeId, KeyPurpose), PublicKey>;

// All TLS certificates found for the nodes in the registry.
type AllTlsCertificates = BTreeMap<NodeId, X509PublicKeyCert>;

// Functions `check_node_crypto_keys_invariants` and `check_node_crypto_keys_soft_invariants`
// check node invariants related to crypto keys:
//  * every node has the required public keys, i.e.:
//     - node signing public key
//     - committee signing public key
//     - DKG dealing encryption public key
//     - TLS certificate
//     - interactive DKG encryption public key
//  * All public keys and TLS certificates have a corresponding node
//  * every node's id (node_id) is correctly derived from its node signing
//    public key
//  * all the public keys and all the TLS certificates belonging to the all the
//    nodes are unique
//  * At most 1 subnet can be an ECDSA signing subnet for a given key_id (for now)
//  * Subnets specified in ECDSA signing subnet lists exists and contain the equivalent key in their configs
//
// It is NOT CHECKED that the crypto keys are fully well-formed or valid, as these
// checks are expensive in terms of computation (about 200 times more expensive then just parsing,
// 400M instructions per node vs. 2M instructions), so for the mainnet state with 1K+ nodes
// the full validation would go over the instruction limit per message.
//
// The "soft invariants" log the results of the checks, and report an error if one occurs,
// but are meant as a non-blocking check, whose result is ignored by the caller.
// The corresponding checks will eventually migrate to the regular, blocking version.
pub(crate) fn check_node_crypto_keys_soft_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    println!("{}crypto_soft_invariants_check_start", LOG_PREFIX);
    let nodes = get_node_records_from_snapshot(snapshot);
    let (pks, certs) = get_all_nodes_public_keys_and_certs(snapshot)?;

    let mut ok_node_count = 0;
    let mut bad_node_count = 0;
    let mut maybe_error: Option<Result<(), InvariantCheckError>> = None;
    for node_id in nodes.keys() {
        // Check that all the nodes' keys and certs are present, and node_id is consistent
        match node_has_all_keys_and_cert_and_valid_node_id(node_id, &pks, &certs) {
            Ok(()) => ok_node_count += 1,
            Err(err) => {
                bad_node_count += 1;
                maybe_error = Some(maybe_error.unwrap_or(Err(err)));
            }
        }
    }

    // Check that all the keys and certs are unique.
    if let Err(err) = nodes_crypto_keys_and_certs_are_unique(pks, certs) {
        maybe_error = Some(maybe_error.unwrap_or(Err(err)));
    }

    let result = maybe_error.unwrap_or(Ok(()));
    let label = if result.is_ok() {
        "crypto_soft_invariants_check_success"
    } else {
        "crypto_soft_invariants_check_failure"
    };
    println!(
        "{}{}: # of ok nodes: {}, # of bad nodes: {}, result: {:?}",
        LOG_PREFIX, label, ok_node_count, bad_node_count, result
    );
    result
}

// See documentation of `check_node_crypto_keys_soft_invariants` above.
pub(crate) fn check_node_crypto_keys_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    check_no_orphaned_node_crypto_records(snapshot)?;
    check_ecdsa_signing_subnet_lists(snapshot)
}

fn node_has_all_keys_and_cert_and_valid_node_id(
    node_id: &NodeId,
    pks: &AllPublicKeys,
    certs: &AllTlsCertificates,
) -> Result<(), InvariantCheckError> {
    let mut maybe_error: Option<Result<(), InvariantCheckError>> = None;
    for key_purpose in [
        KeyPurpose::NodeSigning,
        KeyPurpose::CommitteeSigning,
        KeyPurpose::DkgDealingEncryption,
        KeyPurpose::IDkgMEGaEncryption,
    ] {
        match pks.get(&(*node_id, key_purpose)) {
            Some(pk) => {
                if key_purpose == KeyPurpose::NodeSigning {
                    match node_id_is_consistently_derived(node_id, pk) {
                        Ok(()) => {}
                        Err(err) => {
                            println!("{} {}", LOG_PREFIX, err.msg);
                            maybe_error = Some(maybe_error.unwrap_or(Err(err)));
                        }
                    }
                }
            }
            None => {
                let msg = format!("node {} has no key for purpose {:?} ", node_id, key_purpose);
                println!("{} {}", LOG_PREFIX, msg);
                maybe_error =
                    Some(maybe_error.unwrap_or(Err(InvariantCheckError { msg, source: None })));
            }
        }
    }
    if certs.get(node_id).is_none() {
        let msg = format!("node {} has no TLS cert", node_id);
        println!("{} {}", LOG_PREFIX, msg);
        maybe_error = Some(maybe_error.unwrap_or(Err(InvariantCheckError { msg, source: None })));
    }
    maybe_error.unwrap_or(Ok(()))
}

fn node_id_is_consistently_derived(
    node_id: &NodeId,
    public_key: &PublicKey,
) -> Result<(), InvariantCheckError> {
    let mut maybe_err_msg: Option<String> = None;
    match derive_node_id(public_key) {
        Ok(derived_node_id) => {
            if derived_node_id != *node_id {
                maybe_err_msg = Some(format!(
                    "node {} has an inconsistent NodeSigning key {:?} ",
                    node_id, public_key.key_value
                ));
            }
        }
        Err(err) => {
            maybe_err_msg = Some(format!(
                "node {} has a corrupted NodeSigning key: {:?}",
                node_id, err
            ));
        }
    }
    match maybe_err_msg {
        None => Ok(()),
        Some(msg) => Err(InvariantCheckError { msg, source: None }),
    }
}

// Note: this function intentionally checks that all crypto key material is unique across both
// public keys and TLS certs, just to avoid potential abuse of key material in different contexts.
fn nodes_crypto_keys_and_certs_are_unique(
    pks: AllPublicKeys,
    certs: AllTlsCertificates,
) -> Result<(), InvariantCheckError> {
    let mut unique_pks_and_certs: HashMap<Vec<u8>, NodeId> = HashMap::new();
    let mut maybe_error: Option<Result<(), InvariantCheckError>> = None;
    for ((node_id, _purpose), pk) in pks {
        match unique_pks_and_certs.get(&pk.key_value) {
            Some(prev) => {
                let msg = format!(
                    "nodes {} and {} use the same public key {:?}",
                    prev, node_id, pk.key_value
                );
                println!("{} {}", LOG_PREFIX, msg);
                maybe_error =
                    Some(maybe_error.unwrap_or(Err(InvariantCheckError { msg, source: None })));
            }
            None => {
                unique_pks_and_certs.insert(pk.key_value, node_id);
            }
        }
    }
    for (node_id, cert) in certs {
        match unique_pks_and_certs.get(&cert.certificate_der) {
            Some(prev) => {
                let msg = format!(
                    "nodes {} and {} use the same certificate {:?}",
                    prev, node_id, cert.certificate_der
                );
                println!("{} {}", LOG_PREFIX, msg);
                maybe_error =
                    Some(maybe_error.unwrap_or(Err(InvariantCheckError { msg, source: None })));
            }
            None => {
                unique_pks_and_certs.insert(cert.certificate_der, node_id);
            }
        }
    }
    maybe_error.unwrap_or(Ok(()))
}

// Returns all nodes' public keys and TLS certs in the snapshot.
fn get_all_nodes_public_keys_and_certs(
    snapshot: &RegistrySnapshot,
) -> Result<(AllPublicKeys, AllTlsCertificates), InvariantCheckError> {
    let mut pks = BTreeMap::new();
    let mut certs = BTreeMap::new();

    for (k, v) in snapshot {
        if k.starts_with(CRYPTO_RECORD_KEY_PREFIX.as_bytes()) {
            let key = String::from_utf8(k.to_owned()).map_err(|e| InvariantCheckError {
                msg: format!("invalid crypto node key bytes: {}", e),
                source: None,
            })?;
            let (node_id, key_purpose) =
                maybe_parse_crypto_node_key(&key).ok_or(InvariantCheckError {
                    msg: "invalid crypto node key".to_string(),
                    source: None,
                })?;
            let pk = PublicKey::decode(v.as_slice()).map_err(|e| InvariantCheckError {
                msg: format!("invalid serialised public key: {}", e),
                source: None,
            })?;
            pks.insert((node_id, key_purpose), pk);
        } else if k.starts_with(CRYPTO_TLS_CERT_KEY_PREFIX.as_bytes()) {
            let key = String::from_utf8(k.to_owned()).map_err(|e| InvariantCheckError {
                msg: format!("invalid tls cert key bytes: {}", e),
                source: None,
            })?;
            let node_id = maybe_parse_crypto_tls_cert_key(&key).ok_or(InvariantCheckError {
                msg: "invalid tls cert key".to_string(),
                source: None,
            })?;
            let cert =
                X509PublicKeyCert::decode(v.as_slice()).map_err(|e| InvariantCheckError {
                    msg: format!("invalid serialised public key: {}", e),
                    source: None,
                })?;
            certs.insert(node_id, cert);
        }
    }
    Ok((pks, certs))
}

fn check_ecdsa_signing_subnet_lists(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let subnet_records_map = get_subnet_records_map(snapshot);

    get_all_ecdsa_signing_subnet_list_records(snapshot)
        .iter()
        .try_for_each(|(key_id, ecdsa_signing_subnet_list)| {
            if ecdsa_signing_subnet_list.subnets.len() > 1 {
                return Err(InvariantCheckError {
                    msg: format!(
                        "key_id {} ended up with more than one ECDSA signing subnet",
                        key_id
                    ),
                    source: None,
                });
            }

            let ecdsa_key_id =  match get_ecdsa_key_id_from_signing_subnet_list_key(key_id) {
                Ok(ecdsa_key_id) => ecdsa_key_id,
                Err(error) => {
                    return Err(InvariantCheckError {
                        msg: format!(
                            "Registry key_id {} could not be converted to an ECDSA signature key id: {:?}",
                            key_id,
                            error,
                        ),
                        source: None,
                    });
                }
            };

            ecdsa_signing_subnet_list
                .subnets
                .iter()
                .try_for_each(|subnet_id_bytes| {
                    let subnet_id = subnet_id_try_from_protobuf(subnet_id_bytes.clone()).unwrap();

                    subnet_records_map
                        .get(&make_subnet_record_key(subnet_id).into_bytes())
                        .ok_or(InvariantCheckError {
                            msg: format!(
                                "A non-existent subnet {} was set as the holder of a key_id {}",
                                subnet_id, key_id
                            ),
                            source: None,
                        })?
                        .ecdsa_config
                        .as_ref()
                        .ok_or(InvariantCheckError {
                            msg: format!("The subnet {} does not have an ECDSA config", subnet_id),
                            source: None,
                        })?
                        .key_ids
                        .contains(&(&ecdsa_key_id).into())
                        .then_some(())
                        .ok_or(InvariantCheckError {
                            msg: format!(
                                "The subnet {} does not have the key with {} in its ecdsa configurations",
                                subnet_id, key_id
                            ),
                            source: None,
                        })
                })
        })
}

fn check_no_orphaned_node_crypto_records(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    // Collect unique node_ids from crypto and tls records
    let mut nodes_with_records: HashSet<NodeId> = HashSet::new();
    for key in snapshot.keys() {
        let key_string = String::from_utf8(key.clone()).unwrap();
        if let Some((node_id, _)) = maybe_parse_crypto_node_key(&key_string) {
            nodes_with_records.insert(node_id);
        } else if let Some(node_id) = maybe_parse_crypto_tls_cert_key(&key_string) {
            nodes_with_records.insert(node_id);
        }
    }

    // Filter to only node_ids that do not have a node_record in the registry
    let nodes_with_orphaned_records = nodes_with_records
        .into_iter()
        .filter(|node_id| {
            snapshot
                .get(make_node_record_key(*node_id).as_bytes())
                .is_none()
        })
        .collect::<Vec<_>>();

    // There should be no crypto or tls records without a node_record
    if !nodes_with_orphaned_records.is_empty() {
        return Err(InvariantCheckError {
            msg: format!(
                "There are {} or {} entries without a corresponding {} entry: {:?}",
                CRYPTO_RECORD_KEY_PREFIX,
                CRYPTO_TLS_CERT_KEY_PREFIX,
                NODE_RECORD_KEY_PREFIX,
                nodes_with_orphaned_records
            ),
            source: None,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use ic_config::crypto::CryptoConfig;
    use ic_crypto_node_key_generation::generate_node_keys_once;
    use ic_crypto_node_key_validation::ValidNodePublicKeys;
    use ic_nns_common::registry::encode_or_panic;
    use ic_nns_test_utils::registry::new_current_node_crypto_keys_mutations;
    use ic_protobuf::registry::node::v1::NodeRecord;
    use ic_registry_keys::make_node_record_key;
    use ic_types::crypto::CurrentNodePublicKeys;

    fn insert_node_crypto_keys(
        node_id: &NodeId,
        node_pks: CurrentNodePublicKeys,
        snapshot: &mut RegistrySnapshot,
    ) {
        let mutations = new_current_node_crypto_keys_mutations(*node_id, node_pks);
        for m in mutations {
            snapshot.insert(m.key, m.value);
        }
    }

    fn valid_node_keys_and_node_id() -> (CurrentNodePublicKeys, NodeId) {
        let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
        let node_pks =
            generate_node_keys_once(&config, None).expect("error generating node public keys");
        let node_id = node_pks.node_id();
        (map_to_current_node_public_keys(node_pks), node_id)
    }

    fn map_to_current_node_public_keys(value: ValidNodePublicKeys) -> CurrentNodePublicKeys {
        CurrentNodePublicKeys {
            node_signing_public_key: Some(value.node_signing_key().clone()),
            committee_signing_public_key: Some(value.committee_signing_key().clone()),
            tls_certificate: Some(value.tls_certificate().clone()),
            dkg_dealing_encryption_public_key: Some(value.dkg_dealing_encryption_key().clone()),
            idkg_dealing_encryption_public_key: Some(value.idkg_dealing_encryption_key().clone()),
        }
    }

    fn insert_dummy_node(node_id: &NodeId, snapshot: &mut RegistrySnapshot) {
        snapshot.insert(
            make_node_record_key(node_id.to_owned()).into_bytes(),
            encode_or_panic::<NodeRecord>(&NodeRecord::default()),
        );
    }

    #[test]
    fn node_crypto_keys_invariants_valid_snapshot() {
        // Crypto keys for the test.
        let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
        let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);
        insert_node_crypto_keys(&node_id_2, node_pks_2, &mut snapshot);
        assert!(check_node_crypto_keys_invariants(&snapshot).is_ok());
        assert!(check_node_crypto_keys_soft_invariants(&snapshot).is_ok());
    }

    // TODO(CRP-1450): add tests for "missing" "invalid", and "duplicated" scenarios, so that
    //   these scenarios are tested for all 5 keys of a node.
    #[test]
    fn node_crypto_keys_invariants_missing_committee_key() {
        // Crypto keys for the test.
        let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
        let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);

        let incomplete_node_public_keys = CurrentNodePublicKeys {
            committee_signing_public_key: None,
            ..node_pks_2
        };
        insert_node_crypto_keys(&node_id_2, incomplete_node_public_keys, &mut snapshot);
        let result = check_node_crypto_keys_soft_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("has no key"));
        assert!(err.to_string().contains("CommitteeSigning"));
    }

    #[test]
    fn node_crypto_keys_invariants_missing_node_signing_key() {
        // Crypto keys for the test.
        let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
        let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);

        let incomplete_node_public_keys = CurrentNodePublicKeys {
            node_signing_public_key: None,
            ..node_pks_2
        };
        insert_node_crypto_keys(&node_id_2, incomplete_node_public_keys, &mut snapshot);
        let result = check_node_crypto_keys_soft_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("has no key"));
        assert!(err.to_string().contains("NodeSigning"));
    }

    #[test]
    fn node_crypto_keys_invariants_missing_idkg_dealing_encryption_key() {
        // Crypto keys for the test.
        let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
        let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);

        let incomplete_node_public_keys = CurrentNodePublicKeys {
            idkg_dealing_encryption_public_key: None,
            ..node_pks_2
        };
        insert_node_crypto_keys(&node_id_2, incomplete_node_public_keys, &mut snapshot);
        let result = check_node_crypto_keys_soft_invariants(&snapshot);

        assert_matches!(result,
                    Err(InvariantCheckError{msg: error_message, source: _})
            if error_message.contains("has no key for purpose IDkgMEGaEncryption"));
    }

    #[test]
    fn node_crypto_keys_invariants_missing_tls_cert() {
        // Crypto keys for the test.
        let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
        let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);

        let incomplete_node_public_keys = CurrentNodePublicKeys {
            tls_certificate: None,
            ..node_pks_2
        };
        insert_node_crypto_keys(&node_id_2, incomplete_node_public_keys, &mut snapshot);
        let result = check_node_crypto_keys_soft_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("has no TLS cert"));
    }

    #[test]
    fn node_crypto_keys_invariants_duplicated_committee_key() {
        // Crypto keys for the test.
        let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
        let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, node_pks_1.clone(), &mut snapshot);

        let duplicated_key_node_pks = CurrentNodePublicKeys {
            committee_signing_public_key: node_pks_1.committee_signing_public_key,
            ..node_pks_2
        };
        insert_node_crypto_keys(&node_id_2, duplicated_key_node_pks, &mut snapshot);
        let result = check_node_crypto_keys_soft_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_1.to_string()));
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("the same public key"));
    }

    #[test]
    fn node_crypto_keys_invariants_duplicated_idkg_encryption_key() {
        // Crypto keys for the test.
        let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
        let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, node_pks_1.clone(), &mut snapshot);

        let duplicated_key_node_pks = CurrentNodePublicKeys {
            idkg_dealing_encryption_public_key: node_pks_1.idkg_dealing_encryption_public_key,
            ..node_pks_2
        };
        insert_node_crypto_keys(&node_id_2, duplicated_key_node_pks, &mut snapshot);
        let result = check_node_crypto_keys_soft_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_1.to_string()));
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("the same public key"));
    }

    #[test]
    fn node_crypto_keys_invariants_duplicated_tls_cert() {
        // Crypto keys for the test.
        let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
        let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, node_pks_1.clone(), &mut snapshot);

        let duplicated_cert_node_pks = CurrentNodePublicKeys {
            tls_certificate: node_pks_1.tls_certificate,
            ..node_pks_2
        };
        insert_node_crypto_keys(&node_id_2, duplicated_cert_node_pks, &mut snapshot);
        let result = check_node_crypto_keys_soft_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_1.to_string()));
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("use the same certificate"));
    }

    #[test]
    fn node_crypto_keys_invariants_inconsistent_node_id() {
        // Crypto keys for the test.
        let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();
        let (node_pks_2, node_id_2) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_dummy_node(&node_id_2, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);

        let (node_pks_3, _node_id_3) = valid_node_keys_and_node_id();
        let inconsistent_signing_key_node_pks = CurrentNodePublicKeys {
            node_signing_public_key: node_pks_3.node_signing_public_key,
            ..node_pks_2
        };
        insert_node_crypto_keys(&node_id_2, inconsistent_signing_key_node_pks, &mut snapshot);
        let result = check_node_crypto_keys_soft_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&node_id_2.to_string()));
        assert!(err.to_string().contains("inconsistent NodeSigning key"));
    }

    #[test]
    fn orphaned_crypto_node_signing_pk() {
        let (mut orphaned_keys, missing_node) = valid_node_keys_and_node_id();
        // This leaves only node_signing_pk as orphan.
        orphaned_keys.committee_signing_public_key = None;
        orphaned_keys.tls_certificate = None;
        orphaned_keys.dkg_dealing_encryption_public_key = None;
        orphaned_keys.idkg_dealing_encryption_public_key = None;
        run_test_orphaned_crypto_keys(missing_node, orphaned_keys);
    }

    #[test]
    fn orphaned_crypto_committee_signing_pk() {
        let (mut orphaned_keys, missing_node) = valid_node_keys_and_node_id();
        orphaned_keys.node_signing_public_key = None;
        // This leaves only committee_signing_pk as orphan.
        orphaned_keys.tls_certificate = None;
        orphaned_keys.dkg_dealing_encryption_public_key = None;
        orphaned_keys.idkg_dealing_encryption_public_key = None;
        run_test_orphaned_crypto_keys(missing_node, orphaned_keys);
    }

    #[test]
    fn orphaned_crypto_tls_certificate() {
        let (mut orphaned_keys, missing_node) = valid_node_keys_and_node_id();
        orphaned_keys.node_signing_public_key = None;
        orphaned_keys.committee_signing_public_key = None;
        // This leaves only tls_certificate as orphan.
        orphaned_keys.dkg_dealing_encryption_public_key = None;
        orphaned_keys.idkg_dealing_encryption_public_key = None;
        run_test_orphaned_crypto_keys(missing_node, orphaned_keys);
    }

    #[test]
    fn orphaned_crypto_dkg_dealing_encryption_pk() {
        let (mut orphaned_keys, missing_node) = valid_node_keys_and_node_id();
        orphaned_keys.node_signing_public_key = None;
        orphaned_keys.committee_signing_public_key = None;
        orphaned_keys.tls_certificate = None;
        // This leaves only dkg_dealing_encryption_pk as orphan.
        orphaned_keys.idkg_dealing_encryption_public_key = None;
        run_test_orphaned_crypto_keys(missing_node, orphaned_keys);
    }

    #[test]
    fn orphaned_crypto_idkg_dealing_encryption_pk() {
        let (mut orphaned_keys, missing_node) = valid_node_keys_and_node_id();
        orphaned_keys.node_signing_public_key = None;
        orphaned_keys.committee_signing_public_key = None;
        orphaned_keys.tls_certificate = None;
        orphaned_keys.dkg_dealing_encryption_public_key = None;
        // This leaves only idkg_dealing_encryption_pk as orphan.
        run_test_orphaned_crypto_keys(missing_node, orphaned_keys);
    }

    /// Ensures that if there are any missing keys, the InvariantCheck is triggered for the 'missing_node_id', which
    /// is not given an entry in the nodes table but will have the public_key records created for it
    /// This is useful so that we can run the same test on each individual missing key
    fn run_test_orphaned_crypto_keys(
        missing_node_id: NodeId,
        node_pks_with_missing_entries: CurrentNodePublicKeys,
    ) {
        // Crypto keys for the test.
        let (node_pks_1, node_id_1) = valid_node_keys_and_node_id();

        // Generate and check a valid snapshot.
        let mut snapshot = RegistrySnapshot::new();
        insert_dummy_node(&node_id_1, &mut snapshot);
        insert_node_crypto_keys(&node_id_1, node_pks_1, &mut snapshot);
        insert_node_crypto_keys(
            &missing_node_id,
            node_pks_with_missing_entries,
            &mut snapshot,
        );

        // TODO make this test more robust (all the cases 1 at a time)

        let result = check_node_crypto_keys_invariants(&snapshot);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains(&missing_node_id.to_string()));
        assert_eq!(
            err.to_string(),
            format!(
                "InvariantCheckError: There are {} or {} entries without a corresponding {} entry: [{}]",
                CRYPTO_RECORD_KEY_PREFIX, CRYPTO_TLS_CERT_KEY_PREFIX, NODE_RECORD_KEY_PREFIX, missing_node_id
            )
        );
    }
}
