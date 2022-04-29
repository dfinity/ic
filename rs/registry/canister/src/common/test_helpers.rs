use crate::mutations::common::encode_or_panic;
use crate::mutations::node_management::do_add_node::{
    connection_endpoint_from_string, flow_endpoint_from_string,
};
use crate::registry::Registry;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_nns_test_utils::registry::invariant_compliant_mutation;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_protobuf::registry::subnet::v1::SubnetRecord;
use ic_registry_keys::make_subnet_record_key;
use ic_registry_keys::{make_crypto_node_key, make_node_record_key, make_subnet_list_record_key};
use ic_registry_transport::pb::v1::{
    registry_mutation::Type, RegistryAtomicMutateRequest, RegistryMutation,
};
use ic_registry_transport::{insert, upsert};
use ic_test_utilities::crypto::temp_dir::temp_dir;
use ic_types::crypto::KeyPurpose;

pub fn invariant_compliant_registry() -> Registry {
    let mut registry = Registry::new();
    let mutations = invariant_compliant_mutation();
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
    let subnet_list_mutation = upsert(
        make_subnet_list_record_key().into_bytes(),
        encode_or_panic(subnet_list_record),
    );

    let new_subnet = upsert(
        make_subnet_record_key(subnet_id).into_bytes(),
        encode_or_panic(&subnet_record),
    );

    subnet_list_record.subnets.push(subnet_id.get().into_vec());

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

/// Prepare a mutate request to add the desired of nodes, and returned the IDs
/// of the nodes to be added.
pub fn prepare_registry_with_nodes(nodes: u64) -> (RegistryAtomicMutateRequest, Vec<NodeId>) {
    // Prepare a transaction to add the nodes to the registry
    let mut mutations = Vec::<RegistryMutation>::default();
    let node_ids: Vec<NodeId> = (0..nodes)
        .map(|_| {
            let temp_dir = temp_dir();
            let (node_pks, node_id) = get_node_keys_or_generate_if_missing(temp_dir.path());
            mutations.push(insert(
                &make_crypto_node_key(node_id, KeyPurpose::DkgDealingEncryption).as_bytes(),
                encode_or_panic(&node_pks.dkg_dealing_encryption_pk.unwrap()),
            ));

            let node_key = make_node_record_key(node_id);
            mutations.push(insert(
                node_key.as_bytes(),
                encode_or_panic(&NodeRecord {
                    xnet: Some(connection_endpoint_from_string("128.0.0.1:1234")),
                    http: Some(connection_endpoint_from_string("128.0.0.1:1234")),
                    p2p_flow_endpoints: vec!["123,128.0.0.1:10000"]
                        .iter()
                        .map(|x| flow_endpoint_from_string(x))
                        .collect(),
                    node_operator_id: PrincipalId::new_user_test_id(999).into_vec(),
                    ..Default::default()
                }),
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
