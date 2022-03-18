//! Utilities to intialize and mutate the registry, for tests.

use std::convert::TryFrom;

use assert_matches::assert_matches;
use maplit::btreemap;
use prost::Message;

use canister_test::Canister;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_nns_common::registry::encode_or_panic;
use ic_nns_test_keys::{
    TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL, TEST_USER3_PRINCIPAL, TEST_USER4_PRINCIPAL,
    TEST_USER5_PRINCIPAL, TEST_USER6_PRINCIPAL, TEST_USER7_PRINCIPAL,
};
use ic_protobuf::{
    crypto::v1::NodePublicKeys,
    registry::{
        node::v1::{connection_endpoint::Protocol, ConnectionEndpoint, NodeRecord},
        node_operator::v1::NodeOperatorRecord,
        replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
        routing_table::v1::RoutingTable as RoutingTablePB,
        subnet::v1::{CatchUpPackageContents, SubnetListRecord, SubnetRecord},
    },
};
use ic_registry_keys::{
    make_blessed_replica_version_key, make_catch_up_package_contents_key, make_crypto_node_key,
    make_crypto_threshold_signing_pubkey_key, make_node_operator_record_key, make_node_record_key,
    make_replica_version_key, make_routing_table_record_key, make_subnet_list_record_key,
    make_subnet_record_key,
};
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{
    deserialize_get_value_response, insert,
    pb::v1::{
        registry_mutation::Type, RegistryAtomicMutateRequest, RegistryAtomicMutateResponse,
        RegistryMutation,
    },
    serialize_get_value_request,
};
use ic_test_utilities::{
    crypto::temp_dir::temp_dir,
    types::ids::{node_test_id, subnet_test_id, user_test_id},
};
use ic_types::p2p::build_default_gossip_config;
use ic_types::{crypto::KeyPurpose, NodeId, ReplicaVersion};
use on_wire::bytes;
use registry_canister::mutations::{
    common::decode_registry_value,
    do_add_node::{connection_endpoint_from_string, flow_endpoint_from_string, AddNodePayload},
};

/// ID used in multiple tests.
pub const TEST_ID: u64 = 999;

/// Returns a `RegistryAtomicMutateRequest` containing all the invariant
/// compliant mutations to initialize the registry.
pub fn invariant_compliant_mutation_as_atomic_req() -> RegistryAtomicMutateRequest {
    RegistryAtomicMutateRequest {
        mutations: invariant_compliant_mutation(),
        preconditions: vec![],
    }
}

/// Gets the latest value for the given key and decode it, assuming it
/// represents a serialized T.
///
/// Returns the default T if there is no value.
pub async fn get_value<T: Message + Default>(registry: &Canister<'_>, key: &[u8]) -> T {
    deserialize_get_value_response(
        registry
            .query_(
                "get_value",
                bytes,
                serialize_get_value_request(key.to_vec(), None).unwrap(),
            )
            .await
            .unwrap(),
    )
    .map(|(encoded_value, _version)| T::decode(encoded_value.as_slice()).unwrap())
    .unwrap_or_else(|_| T::default())
}

/// Inserts a value into the registry.
pub async fn insert_value<T: Message + Default>(registry: &Canister<'_>, key: &[u8], value: &T) {
    let response_bytes = registry
        .update_(
            "atomic_mutate",
            bytes,
            encode_or_panic(&RegistryAtomicMutateRequest {
                mutations: vec![RegistryMutation {
                    mutation_type: Type::Insert as i32,
                    key: key.to_vec(),
                    value: encode_or_panic(value),
                }],
                preconditions: vec![],
            }),
        )
        .await
        .unwrap();
    let response = RegistryAtomicMutateResponse::decode(response_bytes.as_slice()).unwrap();
    assert_matches!(response,
        RegistryAtomicMutateResponse {
            errors,
            version: _
        } if errors.is_empty()
    );
}

pub fn routing_table_mutation(rt: &RoutingTable) -> RegistryMutation {
    use ic_protobuf::registry::routing_table::v1 as pb;

    let rt_pb = pb::RoutingTable::from(rt);
    let mut buf = vec![];
    rt_pb.encode(&mut buf).unwrap();
    RegistryMutation {
        mutation_type: Type::Upsert as i32,
        key: make_routing_table_record_key().into_bytes(),
        value: buf,
    }
}

/// Returns a mutation that sets the initial state of the registry to be
/// compliant with its invariants.
pub fn invariant_compliant_mutation() -> Vec<RegistryMutation> {
    let node_operator_pid = user_test_id(TEST_ID);
    let node_pid = node_test_id(TEST_ID);
    let subnet_pid = subnet_test_id(TEST_ID);

    let connection_endpoint = ConnectionEndpoint {
        ip_addr: "128.0.0.1".to_string(),
        port: 12345,
        protocol: Protocol::Http1 as i32,
    };
    let node = NodeRecord {
        node_operator_id: node_operator_pid.get().to_vec(),
        xnet: Some(connection_endpoint.clone()),
        http: Some(connection_endpoint),
        ..Default::default()
    };

    const VERSION_REPLICA_ID: &str = "version_42";
    const MOCK_HASH: &str = "d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1";
    let replica_version = ReplicaVersionRecord {
        release_package_url: "http://release_package.tar.gz".into(),
        release_package_sha256_hex: MOCK_HASH.into(),
    };
    let blessed_replica_version = BlessedReplicaVersions {
        blessed_version_ids: vec![VERSION_REPLICA_ID.to_string()],
    };

    let subnet_list = SubnetListRecord {
        subnets: vec![subnet_pid.get().to_vec()],
    };
    let system_subnet = SubnetRecord {
        membership: vec![node_pid.get().to_vec()],
        subnet_type: i32::from(SubnetType::System),
        replica_version_id: VERSION_REPLICA_ID.to_string(),
        unit_delay_millis: 600,
        gossip_config: Some(build_default_gossip_config()),
        ..Default::default()
    };

    vec![
        insert(
            make_subnet_list_record_key().as_bytes().to_vec(),
            encode_or_panic(&subnet_list),
        ),
        insert(
            make_subnet_record_key(subnet_pid).as_bytes().to_vec(),
            encode_or_panic(&system_subnet),
        ),
        routing_table_mutation(&RoutingTable::default()),
        insert(
            make_node_record_key(node_pid).as_bytes().to_vec(),
            encode_or_panic(&node),
        ),
        insert(
            make_replica_version_key(VERSION_REPLICA_ID)
                .as_bytes()
                .to_vec(),
            encode_or_panic(&replica_version),
        ),
        insert(
            make_blessed_replica_version_key().as_bytes().to_vec(),
            encode_or_panic(&blessed_replica_version),
        ),
    ]
}

/// Make a `NodeOperatorRecord` from the provided `PrincipalId`.
fn make_node_operator_record(principal_id: PrincipalId) -> NodeOperatorRecord {
    NodeOperatorRecord {
        node_allowance: 1,
        node_operator_principal_id: principal_id.into(),
        ..Default::default()
    }
}

/// Make a node record from the provided `NodeOperatorRecord`.
fn make_node_record(node_operator_record: &NodeOperatorRecord) -> NodeRecord {
    let connection_endpoint = ConnectionEndpoint {
        ip_addr: "128.0.0.1".to_string(),
        port: 12345,
        protocol: Protocol::Http1 as i32,
    };
    NodeRecord {
        node_operator_id: node_operator_record.node_operator_principal_id.clone(),
        xnet: Some(connection_endpoint.clone()),
        http: Some(connection_endpoint),
        ..Default::default()
    }
}

/// Setup the registry with a single subnet (containing all the ranges) which
/// has 7 nodes, whose node operator keys we control for testing.
pub fn initial_mutations_for_a_multinode_nns_subnet() -> Vec<RegistryMutation> {
    let nns_subnet_id = subnet_test_id(1);

    let nor1 = make_node_operator_record(*TEST_USER1_PRINCIPAL);
    let nor2 = make_node_operator_record(*TEST_USER2_PRINCIPAL);
    let nor3 = make_node_operator_record(*TEST_USER3_PRINCIPAL);
    let nor4 = make_node_operator_record(*TEST_USER4_PRINCIPAL);
    let nor5 = make_node_operator_record(*TEST_USER5_PRINCIPAL);
    let nor6 = make_node_operator_record(*TEST_USER6_PRINCIPAL);
    let nor7 = make_node_operator_record(*TEST_USER7_PRINCIPAL);

    let nr1 = make_node_record(&nor1);
    let nr1_pid = node_test_id(1);
    let nr2 = make_node_record(&nor2);
    let nr2_pid = node_test_id(2);
    let nr3 = make_node_record(&nor3);
    let nr3_pid = node_test_id(3);
    let nr4 = make_node_record(&nor4);
    let nr4_pid = node_test_id(4);
    let nr5 = make_node_record(&nor5);
    let nr5_pid = node_test_id(5);
    let nr6 = make_node_record(&nor6);
    let nr6_pid = node_test_id(6);
    let nr7 = make_node_record(&nor7);
    let nr7_pid = node_test_id(7);

    const VERSION_REPLICA_ID: &str = "version_42";
    const MOCK_HASH: &str = "d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1";
    let replica_version = ReplicaVersionRecord {
        release_package_url: "http://release_package.tar.gz".into(),
        release_package_sha256_hex: MOCK_HASH.into(),
    };
    let blessed_replica_version = BlessedReplicaVersions {
        blessed_version_ids: vec![VERSION_REPLICA_ID.to_string()],
    };
    let subnet_list = SubnetListRecord {
        subnets: vec![nns_subnet_id.get().to_vec()],
    };
    let system_subnet = SubnetRecord {
        membership: vec![
            nr1_pid.get().to_vec(),
            nr2_pid.get().to_vec(),
            nr3_pid.get().to_vec(),
            nr4_pid.get().to_vec(),
            nr5_pid.get().to_vec(),
            nr6_pid.get().to_vec(),
            nr7_pid.get().to_vec(),
        ],
        subnet_type: i32::from(SubnetType::System),
        replica_version_id: VERSION_REPLICA_ID.to_string(),
        unit_delay_millis: 600,
        gossip_config: Some(build_default_gossip_config()),
        ..Default::default()
    };

    let routing_table = RoutingTable::try_from(btreemap! {
        CanisterIdRange {
           start: CanisterId::from(0),
           end: CanisterId::from(u64::MAX),
        } => nns_subnet_id,
    })
    .unwrap();

    let mut mutations = vec![
        insert(
            make_subnet_list_record_key().as_bytes().to_vec(),
            encode_or_panic(&subnet_list),
        ),
        insert(
            make_subnet_record_key(nns_subnet_id).as_bytes().to_vec(),
            encode_or_panic(&system_subnet),
        ),
        insert(
            make_routing_table_record_key().as_bytes().to_vec(),
            encode_or_panic(&RoutingTablePB::try_from(routing_table).unwrap()),
        ),
        insert(
            make_replica_version_key(VERSION_REPLICA_ID)
                .as_bytes()
                .to_vec(),
            encode_or_panic(&replica_version),
        ),
        insert(
            make_blessed_replica_version_key().as_bytes().to_vec(),
            encode_or_panic(&blessed_replica_version),
        ),
    ];

    for nor in &[nor1, nor2, nor3, nor4, nor5, nor6, nor7] {
        mutations.push(insert(
            make_node_operator_record_key(
                PrincipalId::try_from(&nor.node_operator_principal_id).unwrap(),
            )
            .as_bytes()
            .to_vec(),
            encode_or_panic(nor),
        ));
    }

    for (pid, nr) in &[
        (nr1_pid, nr1),
        (nr2_pid, nr2),
        (nr3_pid, nr3),
        (nr4_pid, nr4),
        (nr5_pid, nr5),
        (nr6_pid, nr6),
        (nr7_pid, nr7),
    ] {
        mutations.push(insert(
            make_node_record_key(*pid).as_bytes().to_vec(),
            encode_or_panic(nr),
        ));
    }

    mutations
}

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
    let replica_version_record = ReplicaVersionRecord::default();
    mutations.push(insert(
        &make_replica_version_key(&replica_version.to_string()),
        encode_or_panic(&replica_version_record),
    ));

    // Subnet record 1
    let subnet_record = SubnetRecord {
        replica_version_id: replica_version.to_string(),
        membership: nodes_in_subnet1_ids
            .iter()
            .map(|id| id.get().into_vec())
            .collect(),
        unit_delay_millis: 600,
        gossip_config: Some(build_default_gossip_config()),
        ..Default::default()
    };
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
        let subnet2_record = SubnetRecord {
            replica_version_id: replica_version.to_string(),
            membership: nodes_in_subnet2_ids
                .iter()
                .map(|id| id.get().into_vec())
                .collect(),
            unit_delay_millis: 600,
            gossip_config: Some(build_default_gossip_config()),
            ..Default::default()
        };
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
        make_subnet_list_record_key().as_bytes(),
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

/// Prepares all the payloads to add a new node, for tests.
pub fn prepare_add_node_payload() -> (AddNodePayload, NodePublicKeys, NodeId) {
    // As the node canister checks for validity of keys, we need to generate them
    // first
    let temp_dir = temp_dir();
    let (node_pks, node_id) = get_node_keys_or_generate_if_missing(temp_dir.path());

    // create payload message
    let node_signing_pk = encode_or_panic(&node_pks.node_signing_pk.clone().unwrap());
    let committee_signing_pk = encode_or_panic(&node_pks.committee_signing_pk.clone().unwrap());
    let ni_dkg_dealing_encryption_pk =
        encode_or_panic(&node_pks.dkg_dealing_encryption_pk.clone().unwrap());
    let transport_tls_cert = encode_or_panic(&node_pks.tls_certificate.clone().unwrap());
    let idkg_dealing_encryption_pk =
        encode_or_panic(&node_pks.idkg_dealing_encryption_pk.clone().unwrap());

    let payload = AddNodePayload {
        node_signing_pk,
        committee_signing_pk,
        ni_dkg_dealing_encryption_pk,
        transport_tls_cert,
        idkg_dealing_encryption_pk: Some(idkg_dealing_encryption_pk),
        xnet_endpoint: "128.0.0.1:1234".to_string(),
        http_endpoint: "128.0.0.1:8123".to_string(),
        p2p_flow_endpoints: vec!["123,128.0.0.1:10000".to_string()],
        prometheus_metrics_endpoint: "128.0.0.1:5555".to_string(),
    };

    (payload, node_pks, node_id)
}
