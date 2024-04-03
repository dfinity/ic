use std::default::Default;
use std::str::FromStr;

use crate::mutations::common::encode_or_panic;
use crate::{common::LOG_PREFIX, mutations::common::decode_registry_value, registry::Registry};
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_nns_common::registry::decode_or_panic;
use ic_protobuf::registry::{
    node::v1::NodeRecord, node_operator::v1::NodeOperatorRecord, subnet::v1::SubnetListRecord,
};
use ic_registry_keys::{
    make_crypto_node_key, make_crypto_tls_cert_key, make_firewall_rules_record_key,
    make_node_operator_record_key, make_node_record_key, make_subnet_list_record_key,
    FirewallRulesScope, NODE_RECORD_KEY_PREFIX,
};
use ic_registry_transport::pb::v1::{RegistryMutation, RegistryValue};
use ic_registry_transport::{delete, insert, update};
use ic_types::crypto::KeyPurpose;
use std::convert::TryFrom;

pub fn find_subnet_for_node(
    registry: &Registry,
    node_id: NodeId,
    subnet_list_record: &SubnetListRecord,
) -> Option<SubnetId> {
    subnet_list_record
        .subnets
        .iter()
        .find(|subnet_id| -> bool {
            let subnet_id = SubnetId::new(PrincipalId::try_from(*subnet_id).unwrap());
            let subnet_record = registry.get_subnet_or_panic(subnet_id);
            subnet_record.membership.contains(&node_id.get().to_vec())
        })
        .map(|subnet_vector| SubnetId::new(PrincipalId::try_from(subnet_vector).unwrap()))
}

pub fn get_subnet_list_record(registry: &Registry) -> SubnetListRecord {
    let RegistryValue {
        value: subnet_list_record_vec,
        version: _,
        deletion_marker: _,
    } = registry
        .get(
            make_subnet_list_record_key().as_bytes(),
            registry.latest_version(),
        )
        .ok_or(format!(
            "{}do_remove_nodes: Subnet List not found in the registry, aborting node removal.",
            LOG_PREFIX
        ))
        .unwrap();

    decode_registry_value::<SubnetListRecord>(subnet_list_record_vec.to_vec())
}

pub fn get_node_operator_id_for_node(
    registry: &Registry,
    node_id: NodeId,
) -> Result<PrincipalId, String> {
    let node_key = make_node_record_key(node_id);
    registry
        .get(node_key.as_bytes(), registry.latest_version())
        .map_or(
            Err(format!("Node Id {:} not found in the registry", node_id)),
            |result| {
                PrincipalId::try_from(
                    decode_registry_value::<NodeRecord>(result.value.to_vec()).node_operator_id,
                )
                .map_err(|_| {
                    format!(
                        "Could not decode node_record's node_operator_id for Node Id {}",
                        node_id
                    )
                })
            },
        )
}

pub fn get_node_operator_record(
    registry: &Registry,
    node_operator_id: PrincipalId,
) -> Result<NodeOperatorRecord, String> {
    let node_operator_key = make_node_operator_record_key(node_operator_id);
    registry
        .get(node_operator_key.as_bytes(), registry.latest_version())
        .map_or(
            Err(format!(
                "Node Operator Id {:} not found in the registry.",
                node_operator_key
            )),
            |result| {
                let decoded = decode_registry_value::<NodeOperatorRecord>(result.value.to_vec());
                Ok(decoded)
            },
        )
}

pub fn make_update_node_operator_mutation(
    node_operator_id: PrincipalId,
    node_operator_record: &NodeOperatorRecord,
) -> RegistryMutation {
    let node_operator_key = make_node_operator_record_key(node_operator_id);
    update(
        node_operator_key.as_bytes(),
        encode_or_panic(node_operator_record),
    )
}

pub fn make_add_node_registry_mutations(
    node_id: NodeId,
    node_record: NodeRecord,
    valid_node_pks: ValidNodePublicKeys,
) -> Vec<RegistryMutation> {
    // Update registry with the new node data
    let add_node_entry = insert(
        make_node_record_key(node_id).as_bytes(),
        encode_or_panic(&node_record),
    );

    // Add the crypto keys
    let add_committee_signing_key = insert(
        make_crypto_node_key(node_id, KeyPurpose::CommitteeSigning).as_bytes(),
        encode_or_panic(valid_node_pks.committee_signing_key()),
    );
    let add_node_signing_key = insert(
        make_crypto_node_key(node_id, KeyPurpose::NodeSigning).as_bytes(),
        encode_or_panic(valid_node_pks.node_signing_key()),
    );
    let add_dkg_dealing_key = insert(
        make_crypto_node_key(node_id, KeyPurpose::DkgDealingEncryption).as_bytes(),
        encode_or_panic(valid_node_pks.dkg_dealing_encryption_key()),
    );
    let add_tls_certificate = insert(
        make_crypto_tls_cert_key(node_id).as_bytes(),
        encode_or_panic(valid_node_pks.tls_certificate()),
    );
    let add_idkg_dealing_key = insert(
        make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption).as_bytes(),
        encode_or_panic(valid_node_pks.idkg_dealing_encryption_key()),
    );

    vec![
        add_node_entry,
        add_committee_signing_key,
        add_node_signing_key,
        add_dkg_dealing_key,
        add_tls_certificate,
        add_idkg_dealing_key,
    ]
}

/// Generate a list of mutations to remove a node and associated data
///
/// This will only generate a mutation if the key is present
pub fn make_remove_node_registry_mutations(
    registry: &Registry,
    node_id: NodeId,
) -> Vec<RegistryMutation> {
    let node_key = make_node_record_key(node_id);
    let committee_signing_key = make_crypto_node_key(node_id, KeyPurpose::CommitteeSigning);
    let node_signing_key = make_crypto_node_key(node_id, KeyPurpose::NodeSigning);
    let dkg_dealing_key = make_crypto_node_key(node_id, KeyPurpose::DkgDealingEncryption);
    let tls_cert_key = make_crypto_tls_cert_key(node_id);
    let idkg_dealing_key = make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption);
    let firewall_ruleset_key = make_firewall_rules_record_key(&FirewallRulesScope::Node(node_id));

    let keys_to_maybe_remove = [
        node_key,
        committee_signing_key,
        node_signing_key,
        dkg_dealing_key,
        tls_cert_key,
        idkg_dealing_key,
        firewall_ruleset_key,
    ];

    let latest_version = registry.latest_version();
    let mutations = keys_to_maybe_remove
        .iter()
        .flat_map(|key| {
            // It is possible, for example, that IDkgMEGaEncryption key is not present
            // or that other keys are not present.  When we have enabled the invariants
            // for the keys being all present for each node_id and removed with the node_id,
            // we can simply return the list of mutations without filtering
            registry
                .get(key.as_bytes(), latest_version)
                .map(|_| delete(key))
        })
        .collect::<Vec<_>>();

    mutations
}

/// Scan through the registry, returning a list of any nodes with the given IP.
pub fn scan_for_nodes_by_ip(registry: &Registry, ip_addr: &str) -> Vec<NodeId> {
    get_key_family::<NodeRecord>(registry, NODE_RECORD_KEY_PREFIX)
        .into_iter()
        .filter_map(|(k, v)| {
            v.http.and_then(|v| {
                (v.ip_addr == ip_addr).then(|| NodeId::from(PrincipalId::from_str(&k).unwrap()))
            })
        })
        .collect()
}

/// Checks if there is a node with the provided IPv4 address
pub fn node_exists_with_ipv4(registry: &Registry, ipv4_addr: &str) -> bool {
    get_key_family::<NodeRecord>(registry, NODE_RECORD_KEY_PREFIX)
        .into_iter()
        .find_map(|(k, v)| {
            v.public_ipv4_config.and_then(|config| {
                (config.ip_addr == ipv4_addr)
                    .then(|| NodeId::from(PrincipalId::from_str(&k).unwrap()))
            })
        })
        .is_some()
}

/// Similar to `get_key_family` on the `RegistryClient`, return a list of
/// tuples, (ID, value).
fn get_key_family<T: prost::Message + Default>(
    registry: &Registry,
    prefix: &str,
) -> Vec<(String, T)> {
    registry
        .store
        .iter()
        // Get the most recent value for all keys that start with this prefix...
        .filter(|(k, _)| k.starts_with(prefix.as_bytes()))
        .map(|(k, v)| (k, v.back().unwrap()))
        // ...skipping any that have been deleted...
        .filter(|(_, v)| !v.deletion_marker)
        // ...and repack them into a tuple of (ID, value).
        .map(|(k, v)| {
            let id = k
                .strip_prefix(prefix.as_bytes())
                .and_then(|v| std::str::from_utf8(v).ok())
                .unwrap()
                .to_string();
            let value = decode_or_panic::<T>(v.value.clone());

            (id, value)
        })
        .collect()
}
