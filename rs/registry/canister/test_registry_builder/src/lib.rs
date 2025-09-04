use std::{collections::BTreeMap, net::SocketAddr};

use ic_base_types::{NodeId, PrincipalId};
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_nns_test_utils::registry::new_node_keys_and_node_id;
use ic_protobuf::registry::{
    crypto::v1::PublicKey,
    node::v1::{ConnectionEndpoint, IPv4InterfaceConfig, NodeRecord},
    subnet::v1::SubnetRecord,
};
use ic_registry_keys::{make_crypto_node_key, make_crypto_tls_cert_key, make_node_record_key};

use ic_registry_transport::{
    insert,
    pb::v1::{RegistryAtomicMutateRequest, RegistryMutation},
};
use ic_types::{crypto::KeyPurpose, ReplicaVersion};
use prost::Message;

pub mod registry_builder;

pub fn prepare_registry_with_nodes_and_node_operator_id(
    start_mutation_id: u8,
    nodes: u64,
    node_operator_id: PrincipalId,
) -> (RegistryAtomicMutateRequest, BTreeMap<NodeId, PublicKey>) {
    // Prepare a transaction to add the nodes to the registry
    let mut mutations = Vec::<RegistryMutation>::default();
    let node_ids_and_dkg_pks: BTreeMap<NodeId, PublicKey> = (0..nodes)
        .map(|id| {
            let (valid_pks, node_id) = new_node_keys_and_node_id();
            let dkg_dealing_encryption_pk = valid_pks.dkg_dealing_encryption_key().clone();
            let effective_id: u8 = start_mutation_id + (id as u8);
            let node_record = NodeRecord {
                xnet: Some(connection_endpoint_from_string(&format!(
                    "128.0.{effective_id}.1:1234"
                ))),
                http: Some(connection_endpoint_from_string(&format!(
                    "[fe80::{effective_id}]:4321"
                ))),
                public_ipv4_config: Some(IPv4InterfaceConfig {
                    ip_addr: format!("128.0.{effective_id}.1"),
                    ..Default::default()
                }),
                node_operator_id: node_operator_id.into_vec(),
                // Preset this field to Some(), in order to allow seamless creation of ApiBoundaryNodeRecord if needed.
                domain: Some(format!("node{effective_id}.example.com")),
                ..Default::default()
            };
            mutations.append(&mut make_add_node_registry_mutations(
                node_id,
                node_record,
                valid_pks,
            ));
            (node_id, dkg_dealing_encryption_pk)
        })
        .collect();

    let mutate_request = RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    };
    (mutate_request, node_ids_and_dkg_pks)
}

pub fn connection_endpoint_from_string(endpoint: &str) -> ConnectionEndpoint {
    endpoint
        .parse::<SocketAddr>()
        .map(|sa| ConnectionEndpoint {
            ip_addr: sa.ip().to_string(),
            port: sa.port() as u32,
        })
        .unwrap()
}

pub fn get_invariant_compliant_subnet_record(node_ids: Vec<NodeId>) -> SubnetRecord {
    SubnetRecord {
        unit_delay_millis: 10,
        replica_version_id: ReplicaVersion::default().into(),
        membership: node_ids.iter().map(|id| id.get().into_vec()).collect(),
        ..Default::default()
    }
    .into()
}

pub fn make_add_node_registry_mutations(
    node_id: NodeId,
    node_record: NodeRecord,
    valid_node_pks: ValidNodePublicKeys,
) -> Vec<RegistryMutation> {
    // Update registry with the new node data
    let add_node_entry = insert(
        make_node_record_key(node_id).as_bytes(),
        node_record.encode_to_vec(),
    );

    // Add the crypto keys
    let add_committee_signing_key = insert(
        make_crypto_node_key(node_id, KeyPurpose::CommitteeSigning).as_bytes(),
        valid_node_pks.committee_signing_key().encode_to_vec(),
    );
    let add_node_signing_key = insert(
        make_crypto_node_key(node_id, KeyPurpose::NodeSigning).as_bytes(),
        valid_node_pks.node_signing_key().encode_to_vec(),
    );
    let add_dkg_dealing_key = insert(
        make_crypto_node_key(node_id, KeyPurpose::DkgDealingEncryption).as_bytes(),
        valid_node_pks.dkg_dealing_encryption_key().encode_to_vec(),
    );
    let add_tls_certificate = insert(
        make_crypto_tls_cert_key(node_id).as_bytes(),
        valid_node_pks.tls_certificate().encode_to_vec(),
    );
    let add_idkg_dealing_key = insert(
        make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption).as_bytes(),
        valid_node_pks.idkg_dealing_encryption_key().encode_to_vec(),
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
