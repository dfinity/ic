use ic_base_types::{PrincipalId, SubnetId};
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_nns_common::registry::{encode_or_panic, SUBNET_LIST_KEY};
use ic_nns_test_utils::registry::invariant_compliant_mutation;
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
use ic_protobuf::registry::{
    replica_version::v1::ReplicaVersionRecord,
    subnet::v1::{SubnetListRecord, SubnetRecord},
};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_node_key,
    make_crypto_threshold_signing_pubkey_key, make_node_record_key, make_replica_version_key,
    make_subnet_record_key,
};
use ic_registry_transport::insert;
use ic_registry_transport::pb::v1::{RegistryAtomicMutateRequest, RegistryMutation};
use ic_test_utilities::crypto::temp_dir::temp_dir;
use ic_types::{crypto::KeyPurpose, NodeId, ReplicaVersion};
use registry_canister::mutations::{
    common::decode_registry_value,
    do_add_node::{connection_endpoint_from_string, flow_endpoint_from_string},
};

/// Prepare the registry initial mutation request for the tests.
///
/// This method will create a subnet record populated with as many nodes as
/// instructed. It will return another set of nodes that are not the
/// part of the subnet.
///
/// Returns:
///     * the initial registry mutate request
///     * the subnet id of the to-be-created subnet
///     * the IDs of the nodes that will be inserted but that will remain
///       unassigned
///     * The mutations that add node records and keys
pub fn prepare_registry(
    num_nodes_in_subnet: usize,
    num_unassigned_nodes: usize,
) -> (
    RegistryAtomicMutateRequest,
    SubnetId,
    Vec<NodeId>,
    Vec<RegistryMutation>,
) {
    prepare_registry_with_two_node_sets(num_nodes_in_subnet, num_unassigned_nodes, false)
}

/// Returns a list of Registry mutations that add Nodes and Subnets (when
/// applied to a Registry)
///
/// This method will create two subnet records each populated with as many nodes
/// as instructed. It returns the node IDs of the 2nd subnet. If
/// `assign_nodes_to_subnet2` is `false`, the 2nd Subnet will not be created and
/// the nodes that would've been assigned to it are left unassigned.
///
/// Returns:
///     * the initial registry mutate request
///     * the subnet id of the first to-be-created subnet
///     * the IDs of the nodes that are either inserted into the 2nd subnet or
///       unassigned
///     * The mutations that add node records and keys
pub fn prepare_registry_with_two_node_sets(
    num_nodes_in_subnet1: usize,
    num_nodes_in_subnet2: usize,
    assign_nodes_to_subnet2: bool,
) -> (
    RegistryAtomicMutateRequest,
    SubnetId,
    Vec<NodeId>,
    Vec<RegistryMutation>,
) {
    // Nodes (both assigned and unassigned)
    let mut mutations = invariant_compliant_mutation();
    let mut node_mutations = Vec::<RegistryMutation>::default();
    let node_ids: Vec<NodeId> = (0..num_nodes_in_subnet2 + num_nodes_in_subnet1)
        .map(|idx| {
            let temp_dir = temp_dir();
            let (node_pks, node_id) = get_node_keys_or_generate_if_missing(temp_dir.path());
            mutations.push(insert(
                &make_crypto_node_key(node_id, KeyPurpose::DkgDealingEncryption).as_bytes(),
                encode_or_panic(&node_pks.dkg_dealing_encryption_pk.clone().unwrap()),
            ));
            node_mutations.push(insert(
                &make_crypto_node_key(node_id, KeyPurpose::DkgDealingEncryption).as_bytes(),
                encode_or_panic(&node_pks.dkg_dealing_encryption_pk.unwrap()),
            ));

            let node_key = make_node_record_key(node_id);
            // Connection endpoints must be well-formed and most must be unique
            let ip_addr_prefix = "128.0.0.1:".to_owned();
            let port = 1234;
            let node_record = NodeRecord {
                xnet: Some(connection_endpoint_from_string(
                    &(ip_addr_prefix.clone() + &(port + idx).to_string()),
                )),
                http: Some(connection_endpoint_from_string(
                    &(ip_addr_prefix + &(port - 1 - idx).to_string()),
                )),
                p2p_flow_endpoints: vec!["123,128.0.0.1:10000"]
                    .iter()
                    .map(|x| flow_endpoint_from_string(x))
                    .collect(),
                node_operator_id: PrincipalId::new_user_test_id(999).to_vec(),
                ..Default::default()
            };
            mutations.push(insert(
                &node_key.as_bytes().to_vec(),
                encode_or_panic(&node_record),
            ));
            node_mutations.push(insert(
                &node_key.as_bytes().to_vec(),
                encode_or_panic(&node_record),
            ));
            node_id
        })
        .collect();
    let nodes_in_subnet1_ids = &node_ids[num_nodes_in_subnet2..];
    let nodes_in_subnet2_ids = &node_ids[..num_nodes_in_subnet2];

    let replica_version = ReplicaVersion::default();
    let mut replica_version_record = ReplicaVersionRecord::default();
    replica_version_record.binary_url = "http://testurl.com/version_1.0".to_string();
    replica_version_record.sha256_hex =
        "f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b".to_string();
    mutations.push(insert(
        &make_replica_version_key(&replica_version.to_string()),
        encode_or_panic(&replica_version_record),
    ));

    // Subnet record 1
    let mut subnet_record = SubnetRecord::default();
    subnet_record.replica_version_id = replica_version.to_string();
    subnet_record.membership = nodes_in_subnet1_ids
        .iter()
        .map(|id| id.get().into_vec())
        .collect();
    let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(17));
    mutations.push(insert(
        make_subnet_record_key(subnet_id).as_bytes(),
        encode_or_panic(&subnet_record),
    ));

    mutations.push(insert(
        make_crypto_threshold_signing_pubkey_key(subnet_id)
            .as_bytes()
            .to_vec(),
        encode_or_panic(&vec![]),
    ));

    // Subnet list record
    let mut subnet_list = decode_registry_value::<SubnetListRecord>(mutations.remove(0).value);
    subnet_list.subnets.push(subnet_id.get().to_vec());

    if assign_nodes_to_subnet2 {
        // Subnet record 2
        let mut subnet2_record = SubnetRecord::default();
        subnet2_record.replica_version_id = replica_version.to_string();
        subnet2_record.membership = nodes_in_subnet2_ids
            .iter()
            .map(|id| id.get().into_vec())
            .collect();
        let subnet2_id = SubnetId::new(PrincipalId::new_subnet_test_id(18));
        mutations.push(insert(
            make_subnet_record_key(subnet2_id).as_bytes(),
            encode_or_panic(&subnet2_record),
        ));

        mutations.push(insert(
            make_crypto_threshold_signing_pubkey_key(subnet2_id)
                .as_bytes()
                .to_vec(),
            encode_or_panic(&vec![]),
        ));

        subnet_list.subnets.push(subnet2_id.get().to_vec());
    }

    mutations.push(insert(
        SUBNET_LIST_KEY.as_bytes(),
        encode_or_panic(&subnet_list),
    ));

    // CUP contents
    let cup_contents_key = make_catch_up_package_contents_key(subnet_id).into_bytes();
    let default_cup_contents = CatchUpPackageContents::default();
    mutations.push(insert(
        cup_contents_key,
        encode_or_panic(&default_cup_contents),
    ));

    let mutate_request = RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    };

    (
        mutate_request,
        subnet_id,
        nodes_in_subnet2_ids.to_vec(),
        node_mutations,
    )
}
