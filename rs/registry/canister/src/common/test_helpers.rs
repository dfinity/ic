use crate::mutations::common::encode_or_panic;
use crate::mutations::do_create_subnet::CreateSubnetPayload;
use crate::mutations::node_management::common::make_add_node_registry_mutations;
use crate::mutations::node_management::do_add_node::{
    connection_endpoint_from_string, flow_endpoint_from_string,
};
use crate::registry::Registry;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_nns_test_utils::registry::{invariant_compliant_mutation, new_node_keys_and_node_id};
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

pub fn invariant_compliant_registry(mutation_id: u8) -> Registry {
    let mut registry = Registry::new();
    let mutations = invariant_compliant_mutation(mutation_id);
    registry.maybe_apply_mutation_internal(mutations);
    registry
}

pub fn empty_mutation() -> Vec<u8> {
    encode_or_panic(&RegistryAtomicMutateRequest {
        mutations: vec![RegistryMutation {
            mutation_type: Type::Upsert as i32,
            key: "_".into(),
            value: "".into(),
        }],
        preconditions: vec![],
    })
}

pub fn add_fake_subnet(
    subnet_id: SubnetId,
    subnet_list_record: &mut SubnetListRecord,
    subnet_record: SubnetRecord,
) -> Vec<RegistryMutation> {
    let new_subnet = upsert(
        make_subnet_record_key(subnet_id).into_bytes(),
        encode_or_panic(&subnet_record),
    );

    subnet_list_record.subnets.push(subnet_id.get().into_vec());
    let subnet_list_mutation = upsert(
        make_subnet_list_record_key().into_bytes(),
        encode_or_panic(subnet_list_record),
    );

    // remaining mutations are added by do_create_subnet but don't
    // trip invariants in current test setups when left out
    vec![
        subnet_list_mutation,
        new_subnet,
        // new_subnet_dkg,
        // new_subnet_threshold_signing_pubkey,
        // routing_table_mutation,
    ]
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
/// of the nodes to be added.
pub fn prepare_registry_with_nodes(
    start_mutation_id: u8,
    nodes: u64,
) -> (RegistryAtomicMutateRequest, Vec<NodeId>) {
    // Prepare a transaction to add the nodes to the registry
    let mut mutations = Vec::<RegistryMutation>::default();
    let node_ids: Vec<NodeId> = (0..nodes)
        .map(|id| {
            let (valid_pks, node_id) = new_node_keys_and_node_id();
            let effective_id: u8 = start_mutation_id + (id as u8);
            let node_record = NodeRecord {
                xnet: Some(connection_endpoint_from_string(&format!(
                    "128.0.{effective_id}.1:1234"
                ))),
                http: Some(connection_endpoint_from_string(&format!(
                    "128.0.{effective_id}.1:4321"
                ))),
                p2p_flow_endpoints: vec![&format!("123,128.0.{effective_id}.1:10000")]
                    .iter()
                    .map(|x| flow_endpoint_from_string(x))
                    .collect(),
                node_operator_id: PrincipalId::new_user_test_id(999).into_vec(),
                ..Default::default()
            };
            mutations.append(&mut make_add_node_registry_mutations(
                node_id,
                node_record,
                valid_pks,
            ));
            node_id
        })
        .collect();

    let mutate_request = RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    };
    (mutate_request, node_ids)
}
