use crate::common::LOG_PREFIX;
use crate::invariants::{
    common::{
        InvariantCheckError, RegistrySnapshot, get_node_records_from_snapshot,
        get_subnet_ids_from_snapshot, get_value_from_snapshot,
    },
    subnet::get_subnet_records_map,
};
use ic_base_types::{NodeId, SubnetId, subnet_id_try_from_protobuf};
use ic_crypto_utils_ni_dkg::extract_subnet_threshold_sig_public_key;
use ic_protobuf::registry::crypto::v1::{PublicKey, X509PublicKeyCert};
use ic_protobuf::registry::subnet::v1::{CatchUpPackageContents, SubnetRecord};
use ic_protobuf::types::v1::MasterPublicKeyId;
use ic_registry_keys::{
    CRYPTO_RECORD_KEY_PREFIX, CRYPTO_TLS_CERT_KEY_PREFIX, NODE_RECORD_KEY_PREFIX,
    get_master_public_key_id_from_signing_subnet_list_key, make_catch_up_package_contents_key,
    make_crypto_threshold_signing_pubkey_key, make_node_record_key, make_subnet_record_key,
    maybe_parse_crypto_node_key, maybe_parse_crypto_tls_cert_key,
};
use ic_registry_subnet_features::ChainKeyConfig;
use ic_types::crypto::KeyPurpose;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use prost::Message;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_crypto_utils_basic_sig::conversions::derive_node_id;

use super::common::get_all_chain_key_signing_subnet_list_records;

#[cfg(test)]
mod tests;

// All crypto public keys found for the nodes or for the subnets in the
// registry.
type AllPublicKeys = BTreeMap<(NodeId, KeyPurpose), PublicKey>;

// All TLS certificates found for the nodes in the registry.
type AllTlsCertificates = BTreeMap<NodeId, X509PublicKeyCert>;

/// Function `check_node_crypto_keys_invariants` checks node invariants related to crypto keys:
///  * every node has the required public keys, i.e.:
///     - node signing public key
///     - committee signing public key
///     - DKG dealing encryption public key
///     - TLS certificate
///     - interactive DKG encryption public key
///  * All public keys and TLS certificates have a corresponding node
///  * every node's id (node_id) is correctly derived from its node signing
///    public key
///  * all the public keys and all the TLS certificates belonging to the all the
///    nodes are unique
///  * At most 1 subnet can be an ECDSA signing subnet for a given key_id (for now)
///  * Subnets specified in ECDSA signing subnet lists exists and contain the equivalent key in their configs
///  * The high threshold signing public key stored explicitly for a subnet matches the one in the
///    CUP of the subnet
///
/// It is NOT CHECKED that the crypto keys are fully well-formed or valid, as these
/// checks are expensive in terms of computation (about 200 times more expensive then just parsing,
/// 400M instructions per node vs. 2M instructions), so for the mainnet state with 1K+ nodes
/// the full validation would go over the instruction limit per message.
pub(crate) fn check_node_crypto_keys_invariants(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    check_node_crypto_keys_exist_and_are_unique(snapshot)?;
    check_no_orphaned_node_crypto_records(snapshot)?;
    check_chain_key_configs(snapshot)?;
    check_chain_key_signing_subnet_lists(snapshot)?;
    check_high_threshold_public_key_matches_the_one_in_cup(snapshot)?;
    Ok(())
}

fn check_node_crypto_keys_exist_and_are_unique(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    println!("{LOG_PREFIX}node_crypto_keys_invariants_check_start");
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
        "node_crypto_keys_invariants_check_success"
    } else {
        "node_crypto_keys_invariants_check_failure"
    };
    println!(
        "{LOG_PREFIX}{label}: # of ok nodes: {ok_node_count}, # of bad nodes: {bad_node_count}, result: {result:?}"
    );
    result
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
                let msg = format!("node {node_id} has no key for purpose {key_purpose:?} ");
                println!("{LOG_PREFIX} {msg}");
                maybe_error =
                    Some(maybe_error.unwrap_or(Err(InvariantCheckError { msg, source: None })));
            }
        }
    }
    if certs.get(node_id).is_none() {
        let msg = format!("node {node_id} has no TLS cert");
        println!("{LOG_PREFIX} {msg}");
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
                "node {node_id} has a corrupted NodeSigning key: {err:?}"
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
                println!("{LOG_PREFIX} {msg}");
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
                println!("{LOG_PREFIX} {msg}");
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
                msg: format!("invalid crypto node key bytes: {e}"),
                source: None,
            })?;
            let (node_id, key_purpose) =
                maybe_parse_crypto_node_key(&key).ok_or(InvariantCheckError {
                    msg: "invalid crypto node key".to_string(),
                    source: None,
                })?;
            let pk = PublicKey::decode(v.as_slice()).map_err(|e| InvariantCheckError {
                msg: format!("invalid serialised public key: {e}"),
                source: None,
            })?;
            pks.insert((node_id, key_purpose), pk);
        } else if k.starts_with(CRYPTO_TLS_CERT_KEY_PREFIX.as_bytes()) {
            let key = String::from_utf8(k.to_owned()).map_err(|e| InvariantCheckError {
                msg: format!("invalid tls cert key bytes: {e}"),
                source: None,
            })?;
            let node_id = maybe_parse_crypto_tls_cert_key(&key).ok_or(InvariantCheckError {
                msg: "invalid tls cert key".to_string(),
                source: None,
            })?;
            let cert =
                X509PublicKeyCert::decode(v.as_slice()).map_err(|e| InvariantCheckError {
                    msg: format!("invalid serialised public key: {e}"),
                    source: None,
                })?;
            certs.insert(node_id, cert);
        }
    }
    Ok((pks, certs))
}

fn check_chain_key_configs(snapshot: &RegistrySnapshot) -> Result<(), InvariantCheckError> {
    let mut subnet_records_map = get_subnet_records_map(snapshot);
    let subnet_id_list = get_subnet_ids_from_snapshot(snapshot);
    for subnet_id in subnet_id_list {
        // Subnets in the subnet list have a subnet record
        let subnet_record: SubnetRecord = subnet_records_map
            .remove(&make_subnet_record_key(subnet_id).into_bytes())
            .unwrap_or_else(|| {
                panic!("Subnet {subnet_id:} is in subnet list but no record exists")
            });

        let Some(chain_key_config_pb) = subnet_record.chain_key_config else {
            continue;
        };

        let chain_key_config =
            ChainKeyConfig::try_from(chain_key_config_pb.clone()).map_err(|err| {
                InvariantCheckError {
                    msg: format!(
                        "ChainKeyConfig {chain_key_config_pb:?} of subnet {subnet_id:} could not be deserialized: {err}",
                    ),
                    source: None,
                }
            })?;

        let mut key_ids = BTreeSet::new();
        for key_config in chain_key_config.key_configs {
            let key_id = key_config.key_id.clone();
            if key_id.requires_pre_signatures()
                && (key_config.pre_signatures_to_create_in_advance.is_none()
                    || key_config.pre_signatures_to_create_in_advance == Some(0))
            {
                return Err(InvariantCheckError {
                    msg: format!(
                        "pre_signatures_to_create_in_advance for key {key_id} of subnet {subnet_id:} must be non-zero",
                    ),
                    source: None,
                });
            }
            if !key_ids.insert(key_id) {
                return Err(InvariantCheckError {
                    msg: format!(
                        "ChainKeyConfig of subnet {:} contains multiple entries for key ID {}.",
                        subnet_id, key_config.key_id,
                    ),
                    source: None,
                });
            }
        }
    }
    Ok(())
}

/// Checks that the chain key signing subnet list is consistent with the chain key configurations
///
/// In particular, this function checks:
/// - That every subnet refered to by the signing subnet list exists
/// - That the subnet has a chain key configuration that contains the corresponding key
fn check_chain_key_signing_subnet_lists(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    let subnet_records_map = get_subnet_records_map(snapshot);

    get_all_chain_key_signing_subnet_list_records(snapshot)
        .iter()
        .try_for_each(|(key_id, chain_key_signing_subnet_list)| {
            let master_key_id =  get_master_public_key_id_from_signing_subnet_list_key(key_id)
                .map_err(|err| InvariantCheckError {
                    msg: format!(
                        "Registry key_id {key_id} could not be converted to an MasterPublicKeyId",
                    ),
                    source: Some(Box::new(err)),
                })?;

            chain_key_signing_subnet_list
                .subnets
                .iter()
                .try_for_each(|subnet_id_bytes| {
                    let subnet_id = subnet_id_try_from_protobuf(subnet_id_bytes.clone())
                    .map_err(|err| InvariantCheckError {
                        msg: "Failed to deserialize subnet id from protobuf".to_string(),
                        source: Some(Box::new(err)),
                    })?;

                    if subnet_records_map
                        .get(&make_subnet_record_key(subnet_id).into_bytes())
                        .ok_or(InvariantCheckError {
                            msg: format!(
                                "A non-existent subnet {subnet_id} was set as the holder of a key_id {key_id}"
                            ),
                            source: None,
                        })?
                        .chain_key_config
                        .as_ref()
                        .ok_or(InvariantCheckError {
                            msg: format!("The subnet {subnet_id} does not have a ChainKeyConfig"),
                            source: None,
                        })?
                        .key_configs
                        .iter()
                        .filter_map(|config| config.key_id.clone())
                        .any(|key| key == MasterPublicKeyId::from(&master_key_id)) {
                            Ok(())
                        } else {
                            Err(InvariantCheckError {
                                msg: format!(
                                    "The subnet {subnet_id} does not have the key with {key_id} in its chain key configurations"
                                ),
                                source: None,
                            })
                        }
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
                "There are {CRYPTO_RECORD_KEY_PREFIX} or {CRYPTO_TLS_CERT_KEY_PREFIX} entries without a corresponding {NODE_RECORD_KEY_PREFIX} entry: {nodes_with_orphaned_records:?}"
            ),
            source: None,
        });
    }
    Ok(())
}

fn check_high_threshold_public_key_matches_the_one_in_cup(
    snapshot: &RegistrySnapshot,
) -> Result<(), InvariantCheckError> {
    println!("{LOG_PREFIX}high_threshold_public_key_matches_the_one_in_cup_check_start");

    let mut bad_subnets: Vec<SubnetId> = vec![];
    let mut ok_subnet_count = 0;
    let mut bad_subnet_count = 0;

    for subnet_id in get_subnet_ids_from_snapshot(snapshot) {
        let high_threshold_public_key_bytes: Option<PublicKey> = get_value_from_snapshot(
            snapshot,
            make_crypto_threshold_signing_pubkey_key(subnet_id),
        );
        let cup_contents_bytes: Option<CatchUpPackageContents> =
            get_value_from_snapshot(snapshot, make_catch_up_package_contents_key(subnet_id));
        if let (Some(high_threshold_public_key_proto), Some(cup_contents)) =
            (high_threshold_public_key_bytes, cup_contents_bytes)
        {
            let high_threshold_public_key = match ThresholdSigPublicKey::try_from(
                high_threshold_public_key_proto,
            ) {
                Ok(pk) => pk,
                Err(e) => {
                    bad_subnets.push(subnet_id);
                    bad_subnet_count += 1;
                    println!(
                        "{LOG_PREFIX}high_threshold_public_key_matches_the_one_in_cup_check: error converting high threshold public key proto to ThresholdSigPublicKey for subnet {subnet_id}: {e:?}"
                    );
                    continue;
                }
            };
            let separate_pk_bytes = high_threshold_public_key.into_bytes();

            let initial_ni_dkg_transcript_high_threshold = match cup_contents
                .initial_ni_dkg_transcript_high_threshold
            {
                Some(initial_ni_dkg_transcript_high_threshold) => {
                    initial_ni_dkg_transcript_high_threshold
                }
                None => {
                    bad_subnets.push(subnet_id);
                    bad_subnet_count += 1;
                    println!(
                        "{LOG_PREFIX}high_threshold_public_key_matches_the_one_in_cup_check: high threshold public key set, but no high threshold public key in cup contents for subnet {subnet_id}"
                    );
                    continue;
                }
            };
            let public_key_bytes_from_cup = match extract_subnet_threshold_sig_public_key(
                &initial_ni_dkg_transcript_high_threshold,
            ) {
                Ok(public_key_bytes_from_cup) => public_key_bytes_from_cup.into_bytes(),
                Err(e) => {
                    bad_subnets.push(subnet_id);
                    bad_subnet_count += 1;
                    println!(
                        "{LOG_PREFIX}high_threshold_public_key_matches_the_one_in_cup_check: error extracting high threshold public key bytes from cup contents for subnet {subnet_id}: {e:?}"
                    );
                    continue;
                }
            };

            if separate_pk_bytes != public_key_bytes_from_cup {
                bad_subnets.push(subnet_id);
                bad_subnet_count += 1;
                println!(
                    "{LOG_PREFIX}high_threshold_public_key_matches_the_one_in_cup_check: explicitly set high threshold public key does not match the one in cup contents for subnet {subnet_id}"
                );
            } else {
                ok_subnet_count += 1;
            }
        } else {
            bad_subnets.push(subnet_id);
            bad_subnet_count += 1;
            println!(
                "{LOG_PREFIX}high_threshold_public_key_matches_the_one_in_cup_check: high threshold public key and/or cup contents not found for subnet {subnet_id}"
            );
        }
    }
    let result = if !bad_subnets.is_empty() {
        Err(InvariantCheckError {
            msg: format!(
                "high_threshold_public_key and cup_contents are inconsistent for subnet(s) {}",
                bad_subnets
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
            source: None,
        })
    } else {
        Ok(())
    };
    let label = if result.is_ok() {
        "high_threshold_public_key_matches_the_one_in_cup_check_success"
    } else {
        "high_threshold_public_key_matches_the_one_in_cup_check_failure"
    };
    println!(
        "{LOG_PREFIX}{label}: # of ok subnets: {ok_subnet_count}, # of bad subnets: {bad_subnet_count}, result: {result:?}"
    );
    result
}
