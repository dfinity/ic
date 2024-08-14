use crate::mutations::do_create_subnet::CreateSubnetPayload;
use crate::mutations::node_management::common::make_add_node_registry_mutations;
use crate::mutations::node_management::do_add_node::connection_endpoint_from_string;
use crate::registry::Registry;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_nns_test_utils::registry::{
    create_subnet_threshold_signing_pubkey_and_cup_mutations, invariant_compliant_mutation,
    new_node_keys_and_node_id,
};
use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_protobuf::registry::node::v1::IPv4InterfaceConfig;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_keys::make_subnet_list_record_key;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_transport::pb::v1::{
    registry_mutation::Type, RegistryAtomicMutateRequest, RegistryMutation,
};
use ic_registry_transport::upsert;
use ic_types::ReplicaVersion;
use prost::Message;
use std::collections::BTreeMap;

pub fn invariant_compliant_registry(mutation_id: u8) -> Registry {
    let mut registry = Registry::new();
    let mutations = invariant_compliant_mutation(mutation_id);
    registry.maybe_apply_mutation_internal(mutations);
    registry
}

pub fn empty_mutation() -> Vec<u8> {
    RegistryAtomicMutateRequest {
        mutations: vec![RegistryMutation {
            mutation_type: Type::Upsert as i32,
            key: "_".into(),
            value: "".into(),
        }],
        preconditions: vec![],
    }
    .encode_to_vec()
}

pub fn add_fake_subnet(
    subnet_id: SubnetId,
    subnet_list_record: &mut SubnetListRecord,
    subnet_record: SubnetRecord,
    node_ids_and_dkg_pks: &BTreeMap<NodeId, PublicKey>,
) -> Vec<RegistryMutation> {
    let new_subnet = upsert(
        make_subnet_record_key(subnet_id).into_bytes(),
        subnet_record.encode_to_vec(),
    );

    subnet_list_record.subnets.push(subnet_id.get().into_vec());
    let subnet_list_mutation = upsert(
        make_subnet_list_record_key().into_bytes(),
        subnet_list_record.encode_to_vec(),
    );

    let mut subnet_threshold_pk_and_cup_mutations =
        create_subnet_threshold_signing_pubkey_and_cup_mutations(subnet_id, node_ids_and_dkg_pks);

    // remaining mutations are added by do_create_subnet but don't
    // trip invariants in current test setups when left out
    subnet_threshold_pk_and_cup_mutations.append(&mut vec![
        subnet_list_mutation,
        new_subnet,
        // new_subnet_dkg,
        // new_subnet_threshold_signing_pubkey,
        // routing_table_mutation,
    ]);
    subnet_threshold_pk_and_cup_mutations
}

/// Get a SubnetRecord that does not fail invariant checks in Registry
pub fn get_invariant_compliant_subnet_record(node_ids: Vec<NodeId>) -> SubnetRecord {
    CreateSubnetPayload {
        unit_delay_millis: 10,
        gossip_retransmission_request_ms: 10_000,
        gossip_registry_poll_period_ms: 2000,
        gossip_pfn_evaluation_period_ms: 50,
        gossip_receive_check_cache_size: 1,
        gossip_max_duplicity: 1,
        gossip_max_chunk_wait_ms: 200,
        gossip_max_artifact_streams_per_peer: 1,
        replica_version_id: ReplicaVersion::default().into(),
        node_ids,
        ..Default::default()
    }
    .into()
}

/// Prepare a mutate request to add the desired of nodes, and returned the IDs
/// of the nodes to be added, together with their NI-DKG dealing encryption public keys.
pub fn prepare_registry_with_nodes(
    start_mutation_id: u8,
    nodes: u64,
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
                node_operator_id: PrincipalId::new_user_test_id(999).into_vec(),
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
