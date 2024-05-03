//! Utilities to initialize and mutate the registry, for tests.

use assert_matches::assert_matches;
use canister_test::Canister;
use ic_base_types::{CanisterId, PrincipalId, RegistryVersion, SubnetId};
use ic_config::crypto::CryptoConfig;
use ic_crypto_node_key_generation::generate_node_keys_once;
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_crypto_test_utils_ni_dkg::{
    dummy_initial_dkg_transcript, initial_dkg_transcript, InitialNiDkgConfig,
};
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_crypto_utils_ni_dkg::extract_threshold_sig_public_key;
use ic_nervous_system_common_test_keys::{
    TEST_USER1_PRINCIPAL, TEST_USER2_PRINCIPAL, TEST_USER3_PRINCIPAL, TEST_USER4_PRINCIPAL,
    TEST_USER5_PRINCIPAL, TEST_USER6_PRINCIPAL, TEST_USER7_PRINCIPAL,
};
use ic_nns_common::registry::encode_or_panic;
use ic_protobuf::registry::subnet::v1::{EcdsaConfig, InitialNiDkgTranscriptRecord};
use ic_protobuf::registry::{
    crypto::v1::{PublicKey, X509PublicKeyCert},
    node::v1::{ConnectionEndpoint, NodeRecord},
    node_operator::v1::NodeOperatorRecord,
    replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    routing_table::v1::RoutingTable as RoutingTablePB,
    subnet::v1::{CatchUpPackageContents, SubnetListRecord, SubnetRecord},
};
use ic_registry_keys::{
    make_blessed_replica_versions_key, make_catch_up_package_contents_key, make_crypto_node_key,
    make_crypto_threshold_signing_pubkey_key, make_crypto_tls_cert_key,
    make_node_operator_record_key, make_node_record_key, make_replica_version_key,
    make_routing_table_record_key, make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{
    deserialize_get_value_response, insert,
    pb::v1::{
        registry_mutation::Type, RegistryAtomicMutateRequest, RegistryAtomicMutateResponse,
        RegistryMutation,
    },
    serialize_get_value_request, Error,
};
use ic_test_utilities_types::ids::{subnet_test_id, user_test_id};
use ic_types::crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTargetId, NiDkgTranscript};
use ic_types::{
    crypto::{CurrentNodePublicKeys, KeyPurpose},
    p2p::build_default_gossip_config,
    NodeId, ReplicaVersion,
};
use maplit::btreemap;
use on_wire::bytes;
use prost::Message;
use rand::RngCore;
use registry_canister::mutations::{
    common::decode_registry_value,
    node_management::{
        common::make_add_node_registry_mutations,
        do_add_node::{connection_endpoint_from_string, AddNodePayload},
    },
};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;

/// ID used in multiple tests.
pub const TEST_ID: u64 = 999;

/// Value used to initialize initial registry records in tests.
///
/// The type is `u8` to make it easy to use this constant for parameterizing IP addresses,
/// usually as follows:
/// ```
/// let ip_addr = format!("192.0.{mutation_id}.{node_id}");
/// ```
/// where `mutation_id` is initialized with `INITIAL_MUTATION_ID` (and incremented as needed, e.g., to avoid
/// endpoint collisions; see `registry_canister::invariants::endpoint::check_endpoint_invariants`)
/// and `node_id` is an `u8` value identifying the node.
///
/// Note: The value `0` is reserved for `ic_replica_tests::get_ic_config`.
pub const INITIAL_MUTATION_ID: u8 = 1;

/// Returns a `RegistryAtomicMutateRequest` containing all the invariant
/// compliant mutations to initialize the registry.
///
/// The argument `mutation_id` should be specified to a `u8` value that is
/// unique within this registry instance.
pub fn invariant_compliant_mutation_as_atomic_req(mutation_id: u8) -> RegistryAtomicMutateRequest {
    RegistryAtomicMutateRequest {
        mutations: invariant_compliant_mutation(mutation_id),
        preconditions: vec![],
    }
}
/// Returns a Result with either an Option(T) or a ic_registry_transport::Error
pub async fn get_value_result<T: Message + Default>(
    registry: &Canister<'_>,
    key: &[u8],
) -> Result<Option<T>, Error> {
    match deserialize_get_value_response(
        registry
            .query_(
                "get_value",
                bytes,
                serialize_get_value_request(key.to_vec(), None).unwrap(),
            )
            .await
            .unwrap(),
    ) {
        Ok((encoded_value, _version)) => Ok(Some(T::decode(encoded_value.as_slice()).unwrap())),
        Err(error) => match error {
            Error::KeyNotPresent(_) => Ok(None),
            _ => Err(error),
        },
    }
}

/// Gets the latest value for the given key and decode it, assuming it
/// represents a serialized T.
///
/// Returns None if there is no value.
///
/// Panics on other registry_transport errors.
pub async fn get_value<T: Message + Default>(registry: &Canister<'_>, key: &[u8]) -> Option<T> {
    get_value_result::<T>(registry, key).await.unwrap()
}

/// Gets the latest value for the given key and decode it, assuming it
/// represents a serialized T.
///
/// Panics if there is no T
pub async fn get_value_or_panic<T: Message + Default>(registry: &Canister<'_>, key: &[u8]) -> T {
    get_value::<T>(registry, key).await.unwrap()
}

pub async fn get_node_record(registry: &Canister<'_>, node_id: NodeId) -> Option<NodeRecord> {
    get_value::<NodeRecord>(registry, make_node_record_key(node_id).as_bytes()).await
}

pub async fn get_committee_signing_key(
    registry: &Canister<'_>,
    node_id: NodeId,
) -> Option<PublicKey> {
    get_value::<PublicKey>(
        registry,
        make_crypto_node_key(node_id, KeyPurpose::CommitteeSigning).as_bytes(),
    )
    .await
}

pub async fn get_node_signing_key(registry: &Canister<'_>, node_id: NodeId) -> Option<PublicKey> {
    get_value::<PublicKey>(
        registry,
        make_crypto_node_key(node_id, KeyPurpose::NodeSigning).as_bytes(),
    )
    .await
}

pub async fn get_dkg_dealing_key(registry: &Canister<'_>, node_id: NodeId) -> Option<PublicKey> {
    get_value::<PublicKey>(
        registry,
        make_crypto_node_key(node_id, KeyPurpose::DkgDealingEncryption).as_bytes(),
    )
    .await
}

pub async fn get_transport_tls_certificate(
    registry: &Canister<'_>,
    node_id: NodeId,
) -> Option<X509PublicKeyCert> {
    get_value::<X509PublicKeyCert>(registry, make_crypto_tls_cert_key(node_id).as_bytes()).await
}

pub async fn get_idkg_dealing_encryption_key(
    registry: &Canister<'_>,
    node_id: NodeId,
) -> Option<PublicKey> {
    get_value::<PublicKey>(
        registry,
        make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption).as_bytes(),
    )
    .await
}

pub async fn get_node_operator_record(
    registry: &Canister<'_>,
    principal_id: PrincipalId,
) -> Option<NodeOperatorRecord> {
    get_value::<NodeOperatorRecord>(
        registry,
        make_node_operator_record_key(principal_id).as_bytes(),
    )
    .await
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
///
/// The argument `mutation_id` should be specified to a `u8` value that is
/// unique within this registry instance.
pub fn invariant_compliant_mutation(mutation_id: u8) -> Vec<RegistryMutation> {
    let subnet_pid = subnet_test_id(TEST_ID);
    invariant_compliant_mutation_with_subnet_id(mutation_id, subnet_pid, None)
}

pub fn invariant_compliant_mutation_with_subnet_id(
    mutation_id: u8,
    subnet_pid: SubnetId,
    ecdsa_config: Option<EcdsaConfig>,
) -> Vec<RegistryMutation> {
    let node_operator_pid = user_test_id(TEST_ID);

    let (valid_pks, node_id) = new_node_keys_and_node_id();

    let mut threshold_pk_and_cup_mutations =
        create_subnet_threshold_signing_pubkey_and_cup_mutations(
            subnet_pid,
            &btreemap!(node_id => valid_pks.dkg_dealing_encryption_key().clone()),
        );

    let node_record = {
        let ip_addr = format!("128.0.{mutation_id}.1");
        let xnet_connection_endpoint = ConnectionEndpoint {
            ip_addr: ip_addr.clone(),
            port: 1234,
        };
        let http_connection_endpoint = ConnectionEndpoint {
            ip_addr,
            port: 4321,
        };
        NodeRecord {
            node_operator_id: node_operator_pid.get().to_vec(),
            xnet: Some(xnet_connection_endpoint),
            http: Some(http_connection_endpoint),
            ..Default::default()
        }
    };
    const MOCK_HASH: &str = "d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1";
    let release_package_url = "http://release_package.tar.gz".to_string();
    let replica_version_id = ReplicaVersion::default().to_string();
    let replica_version = ReplicaVersionRecord {
        release_package_sha256_hex: MOCK_HASH.into(),
        release_package_urls: vec![release_package_url],
        guest_launch_measurement_sha256_hex: None,
    };
    let blessed_replica_version = BlessedReplicaVersions {
        blessed_version_ids: vec![replica_version_id.clone()],
    };

    let subnet_list = SubnetListRecord {
        subnets: vec![subnet_pid.get().to_vec()],
    };
    let system_subnet = SubnetRecord {
        membership: vec![node_id.get().to_vec()],
        subnet_type: i32::from(SubnetType::System),
        replica_version_id: replica_version_id.clone(),
        unit_delay_millis: 600,
        gossip_config: Some(build_default_gossip_config()),
        ecdsa_config,
        ..Default::default()
    };

    let mut mutations = vec![
        insert(
            make_subnet_list_record_key().as_bytes(),
            encode_or_panic(&subnet_list),
        ),
        insert(
            make_subnet_record_key(subnet_pid).as_bytes(),
            encode_or_panic(&system_subnet),
        ),
        routing_table_mutation(&RoutingTable::default()),
        insert(
            make_replica_version_key(replica_version_id).as_bytes(),
            encode_or_panic(&replica_version),
        ),
        insert(
            make_blessed_replica_versions_key().as_bytes(),
            encode_or_panic(&blessed_replica_version),
        ),
    ];
    mutations.append(&mut make_add_node_registry_mutations(
        node_id,
        node_record,
        valid_pks,
    ));
    mutations.append(&mut threshold_pk_and_cup_mutations);
    mutations
}

// NOTE: the secret keys corresponding to the public keys returned by this helper are lost
//   when the helper completes (they are erased when `_temp_dir` goes out of scope).
//   This is intended, as this helper is for creating a valid registry.
pub fn new_node_keys_and_node_id() -> (ValidNodePublicKeys, NodeId) {
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let npks = generate_node_keys_once(&config, None).unwrap_or_else(|_| {
        panic!(
            "Generation of new node keys with CryptoConfig {:?} failed",
            &config
        )
    });
    let node_id = npks.node_id();
    (npks, node_id)
}

pub fn new_current_node_crypto_keys_mutations(
    node_id: NodeId,
    npks: CurrentNodePublicKeys,
) -> Vec<RegistryMutation> {
    let mut mutations: Vec<RegistryMutation> = vec![];
    if let Some(pk) = &npks.node_signing_public_key {
        mutations.push(insert(
            make_crypto_node_key(node_id, KeyPurpose::NodeSigning),
            encode_or_panic(pk),
        ));
    };
    if let Some(pk) = &npks.committee_signing_public_key {
        mutations.push(insert(
            make_crypto_node_key(node_id, KeyPurpose::CommitteeSigning),
            encode_or_panic(pk),
        ));
    };
    if let Some(pk) = &npks.dkg_dealing_encryption_public_key {
        mutations.push(insert(
            make_crypto_node_key(node_id, KeyPurpose::DkgDealingEncryption),
            encode_or_panic(pk),
        ));
    };
    if let Some(pk) = &npks.idkg_dealing_encryption_public_key {
        mutations.push(insert(
            make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption),
            encode_or_panic(pk),
        ));
    };
    if let Some(pk) = &npks.tls_certificate {
        mutations.push(insert(
            make_crypto_tls_cert_key(node_id),
            encode_or_panic(pk),
        ));
    };
    mutations
}

pub fn new_node_crypto_keys_mutations(
    node_id: NodeId,
    npks: &ValidNodePublicKeys,
) -> Vec<RegistryMutation> {
    let current_npks = CurrentNodePublicKeys {
        node_signing_public_key: Some(npks.node_signing_key().clone()),
        committee_signing_public_key: Some(npks.committee_signing_key().clone()),
        tls_certificate: Some(npks.tls_certificate().clone()),
        dkg_dealing_encryption_public_key: Some(npks.dkg_dealing_encryption_key().clone()),
        idkg_dealing_encryption_public_key: Some(npks.idkg_dealing_encryption_key().clone()),
    };
    new_current_node_crypto_keys_mutations(node_id, current_npks)
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
    let id = node_operator_record
        .node_operator_principal_id
        .iter()
        .fold(0, |acc: u32, v| (acc + (*v as u32)) % 255) as u8;
    let xnet_connection_endpoint = ConnectionEndpoint {
        ip_addr: format!("128.0.{id}.1"),
        port: 1234,
    };
    let http_connection_endpoint = ConnectionEndpoint {
        ip_addr: format!("128.0.{id}.1"),
        port: 4321,
    };
    NodeRecord {
        node_operator_id: node_operator_record.node_operator_principal_id.clone(),
        xnet: Some(xnet_connection_endpoint),
        http: Some(http_connection_endpoint),
        ..Default::default()
    }
}

fn get_new_node_id_and_mutations(
    nor: &NodeOperatorRecord,
    subnet_id: SubnetId,
) -> (NodeId, Vec<RegistryMutation>) {
    let (valid_pks, node_id) = new_node_keys_and_node_id();
    let dkg_dealing_encryption_pk = valid_pks.dkg_dealing_encryption_key().clone();
    let nr = make_node_record(nor);
    let mut mutations = make_add_node_registry_mutations(node_id, nr, valid_pks);
    let mut subnet_threshold_pk_and_cup_mutations =
        create_subnet_threshold_signing_pubkey_and_cup_mutations(
            subnet_id,
            &btreemap!(node_id => dkg_dealing_encryption_pk),
        );
    mutations.append(&mut subnet_threshold_pk_and_cup_mutations);
    (node_id, mutations)
}

pub fn create_subnet_threshold_signing_pubkey_and_cup_mutations(
    subnet_id: SubnetId,
    receiver_keys: &BTreeMap<NodeId, PublicKey>,
) -> Vec<RegistryMutation> {
    // TODO: CRP-2345: Refactor such that the `ReproducibleRng` is not instantiated here, but at
    //  the test initialization, and passed down to this function.
    let rng = &mut ReproducibleRng::new();
    let subnet_transcript = generate_nidkg_initial_transcript(
        receiver_keys,
        subnet_test_id(rng.next_u64()),
        NiDkgTag::HighThreshold,
        RegistryVersion::new(1),
        rng,
    );
    // Threshold signing public key
    let subnet_threshold_sig_pk =
        extract_threshold_sig_public_key(&subnet_transcript.internal_csp_transcript)
            .expect("error extracting threshold sig public key from internal CSP transcript");

    // CUP contents
    let cup_contents_key = make_catch_up_package_contents_key(subnet_id).into_bytes();
    let cup_contents = CatchUpPackageContents {
        initial_ni_dkg_transcript_high_threshold: Some(InitialNiDkgTranscriptRecord::from(
            subnet_transcript,
        )),
        ..dummy_cup_for_subnet(receiver_keys.keys().copied().collect())
    };

    vec![
        insert(
            make_crypto_threshold_signing_pubkey_key(subnet_id).as_bytes(),
            encode_or_panic(&PublicKey::from(subnet_threshold_sig_pk)),
        ),
        insert(cup_contents_key, encode_or_panic(&cup_contents)),
    ]
}

/// This creates a CatchupPackageContents for nodes that would be part of as subnet
/// which is necessary if the underlying IC test machinery knows about the subnets you added
/// to your registry
fn dummy_cup_for_subnet(nodes: Vec<NodeId>) -> CatchUpPackageContents {
    let low_threshold_transcript_record =
        dummy_initial_dkg_transcript(nodes.clone(), NiDkgTag::LowThreshold);
    let high_threshold_transcript_record =
        dummy_initial_dkg_transcript(nodes, NiDkgTag::HighThreshold);

    CatchUpPackageContents {
        initial_ni_dkg_transcript_low_threshold: Some(low_threshold_transcript_record),
        initial_ni_dkg_transcript_high_threshold: Some(high_threshold_transcript_record),
        ..Default::default()
    }
}

/// Setup the registry with a single subnet (containing all the ranges) which
/// has 7 nodes, whose node operator keys we control for testing.
pub fn initial_mutations_for_a_multinode_nns_subnet() -> Vec<RegistryMutation> {
    let nns_subnet_id = subnet_test_id(1);

    let mut node_operator: Vec<NodeOperatorRecord> = vec![];
    for principal_id in &[
        *TEST_USER1_PRINCIPAL,
        *TEST_USER2_PRINCIPAL,
        *TEST_USER3_PRINCIPAL,
        *TEST_USER4_PRINCIPAL,
        *TEST_USER5_PRINCIPAL,
        *TEST_USER6_PRINCIPAL,
        *TEST_USER7_PRINCIPAL,
    ] {
        node_operator.push(make_node_operator_record(*principal_id));
    }

    let mut add_node_mutations = vec![];
    let mut node_id = vec![];
    for nor in &node_operator {
        let (id, mut mutations) = get_new_node_id_and_mutations(nor, nns_subnet_id);
        node_id.push(id);
        add_node_mutations.append(&mut mutations);
    }

    let replica_version_id = ReplicaVersion::default().to_string();
    const MOCK_HASH: &str = "d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1";
    let release_package_url = "http://release_package.tar.gz".to_string();
    let replica_version = ReplicaVersionRecord {
        release_package_sha256_hex: MOCK_HASH.into(),
        release_package_urls: vec![release_package_url],
        guest_launch_measurement_sha256_hex: None,
    };
    let blessed_replica_version = BlessedReplicaVersions {
        blessed_version_ids: vec![replica_version_id.clone()],
    };
    let subnet_list = SubnetListRecord {
        subnets: vec![nns_subnet_id.get().to_vec()],
    };
    let system_subnet = SubnetRecord {
        membership: node_id.iter().map(|id| id.get().to_vec()).collect(),
        subnet_type: i32::from(SubnetType::System),
        replica_version_id: replica_version_id.clone(),
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
            make_subnet_list_record_key().as_bytes(),
            encode_or_panic(&subnet_list),
        ),
        insert(
            make_subnet_record_key(nns_subnet_id).as_bytes(),
            encode_or_panic(&system_subnet),
        ),
        insert(
            make_routing_table_record_key().as_bytes(),
            encode_or_panic(&RoutingTablePB::from(routing_table)),
        ),
        insert(
            make_replica_version_key(replica_version_id).as_bytes(),
            encode_or_panic(&replica_version),
        ),
        insert(
            make_blessed_replica_versions_key().as_bytes(),
            encode_or_panic(&blessed_replica_version),
        ),
    ];

    for nor in &node_operator {
        mutations.push(insert(
            make_node_operator_record_key(
                PrincipalId::try_from(&nor.node_operator_principal_id).unwrap(),
            )
            .as_bytes(),
            encode_or_panic(nor),
        ));
    }

    mutations.append(&mut add_node_mutations);
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
    let (mutate_request, subnet_id, _, nodes_in_subnet2_ids, node_mutations) =
        prepare_registry_with_two_node_sets(num_nodes_in_subnet, num_unassigned_nodes, false);
    (
        mutate_request,
        subnet_id,
        nodes_in_subnet2_ids,
        node_mutations,
    )
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
///     * the subnet id of the second to-be-created subnet if `assign_nodes_to_subnet2` is `true`
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
    Option<SubnetId>,
    Vec<NodeId>,
    Vec<RegistryMutation>,
) {
    // Nodes (both assigned and unassigned)
    let mut mutations = invariant_compliant_mutation(INITIAL_MUTATION_ID);
    let mut node_mutations = Vec::<RegistryMutation>::default();
    let node_ids_and_dkg_keys_subnet_1 = generate_node_keys_and_add_node_record_and_key_mutations(
        &mut mutations,
        &mut node_mutations,
        0,
        num_nodes_in_subnet1,
    );
    let node_ids_and_dkg_keys_subnet_2 = generate_node_keys_and_add_node_record_and_key_mutations(
        &mut mutations,
        &mut node_mutations,
        num_nodes_in_subnet1,
        num_nodes_in_subnet2,
    );

    let replica_version = ReplicaVersion::default();

    // Subnet record 1
    let subnet_record = SubnetRecord {
        replica_version_id: replica_version.to_string(),
        membership: node_ids_and_dkg_keys_subnet_1
            .keys()
            .map(|id| id.get().into_vec())
            .collect(),
        unit_delay_millis: 600,
        gossip_config: Some(build_default_gossip_config()),
        subnet_type: ic_protobuf::registry::subnet::v1::SubnetType::Application as i32,
        ..Default::default()
    };
    let subnet_id = SubnetId::new(PrincipalId::new_subnet_test_id(17));
    mutations.push(insert(
        make_subnet_record_key(subnet_id).as_bytes(),
        encode_or_panic(&subnet_record),
    ));

    let mut threshold_signing_pk_and_cup_mutations_subnet_1 =
        create_subnet_threshold_signing_pubkey_and_cup_mutations(
            subnet_id,
            &node_ids_and_dkg_keys_subnet_1,
        );
    mutations.append(&mut threshold_signing_pk_and_cup_mutations_subnet_1);

    // Subnet list record
    let mut subnet_list = decode_registry_value::<SubnetListRecord>(mutations.remove(0).value);
    subnet_list.subnets.push(subnet_id.get().to_vec());

    let mut subnet2_id_option = None;
    if assign_nodes_to_subnet2 {
        // Subnet record 2
        let subnet2_record = SubnetRecord {
            replica_version_id: replica_version.to_string(),
            membership: node_ids_and_dkg_keys_subnet_2
                .keys()
                .map(|id| id.get().into_vec())
                .collect(),
            unit_delay_millis: 600,
            gossip_config: Some(build_default_gossip_config()),
            subnet_type: ic_protobuf::registry::subnet::v1::SubnetType::Application as i32,
            ..Default::default()
        };
        let subnet2_id = SubnetId::new(PrincipalId::new_subnet_test_id(18));
        subnet2_id_option = Some(subnet2_id);
        mutations.push(insert(
            make_subnet_record_key(subnet2_id).as_bytes(),
            encode_or_panic(&subnet2_record),
        ));

        let mut threshold_signing_pk_and_cup_mutations_subnet_2 =
            create_subnet_threshold_signing_pubkey_and_cup_mutations(
                subnet2_id,
                &node_ids_and_dkg_keys_subnet_2,
            );
        mutations.append(&mut threshold_signing_pk_and_cup_mutations_subnet_2);

        subnet_list.subnets.push(subnet2_id.get().to_vec());
    }

    mutations.push(insert(
        make_subnet_list_record_key().as_bytes(),
        encode_or_panic(&subnet_list),
    ));

    let mutate_request = RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    };

    (
        mutate_request,
        subnet_id,
        subnet2_id_option,
        node_ids_and_dkg_keys_subnet_2.keys().cloned().collect(),
        node_mutations,
    )
}

/// Generates node keys for `num_nodes_in_subnet` nodes, with node IDs starting at `node_id_offset`.
/// Also add the node record and node key mutations to the provided `mutations` and `node_mutations`
/// `RegistryMutation` vectors.
///
/// Returns a `BTreeMap` with the node IDs and the DKG dealing encryption keys of the nodes.
fn generate_node_keys_and_add_node_record_and_key_mutations(
    mutations: &mut Vec<RegistryMutation>,
    node_mutations: &mut Vec<RegistryMutation>,
    node_id_offset: usize,
    num_nodes_in_subnet: usize,
) -> BTreeMap<NodeId, PublicKey> {
    (node_id_offset..(node_id_offset + num_nodes_in_subnet))
        .map(|id| {
            let (node_pks, node_id) = new_node_keys_and_node_id();
            let mut crypto_keys_mutations = new_node_crypto_keys_mutations(node_id, &node_pks);
            mutations.append(&mut crypto_keys_mutations.clone());
            node_mutations.append(&mut crypto_keys_mutations);
            let node_key = make_node_record_key(node_id);
            // Connection endpoints must be well-formed and most must be unique
            let effective_id = 1 + INITIAL_MUTATION_ID + (id as u8);
            let ip_addr_prefix = format!("128.0.{effective_id}.1:");
            let node_record = NodeRecord {
                xnet: Some(connection_endpoint_from_string(&format!(
                    "{ip_addr_prefix}1234"
                ))),
                http: Some(connection_endpoint_from_string(&format!(
                    "{ip_addr_prefix}4321"
                ))),
                node_operator_id: PrincipalId::new_user_test_id(999).to_vec(),
                ..Default::default()
            };
            mutations.push(insert(node_key.as_bytes(), encode_or_panic(&node_record)));
            node_mutations.push(insert(node_key.as_bytes(), encode_or_panic(&node_record)));
            (node_id, node_pks.dkg_dealing_encryption_key().clone())
        })
        .collect()
}

pub fn generate_nidkg_initial_transcript(
    receiver_keys: &BTreeMap<NodeId, PublicKey>,
    dealer_subnet_id: SubnetId,
    dkg_tag: NiDkgTag,
    registry_version: RegistryVersion,
    rng: &mut ReproducibleRng,
) -> NiDkgTranscript {
    let mut target_id_bytes = [0u8; 32];
    rng.fill_bytes(&mut target_id_bytes);
    let target_id = NiDkgTargetId::new(target_id_bytes);
    let nodes_set: BTreeSet<NodeId> = receiver_keys.keys().cloned().collect();
    let initial_dkg_config = InitialNiDkgConfig::new(
        &nodes_set,
        dealer_subnet_id,
        dkg_tag,
        target_id,
        registry_version,
    );
    initial_dkg_transcript(initial_dkg_config, receiver_keys, rng)
}

/// Prepares all the payloads to add a new node, for tests.
pub fn prepare_add_node_payload(mutation_id: u8) -> (AddNodePayload, ValidNodePublicKeys) {
    // As the node canister checks for validity of keys, we need to generate them
    // first
    let (config, _temp_dir) = CryptoConfig::new_in_temp_dir();
    let node_public_keys =
        generate_node_keys_once(&config, None).expect("error generating node public keys");

    // create payload message
    let node_signing_pk = encode_or_panic(node_public_keys.node_signing_key());
    let committee_signing_pk = encode_or_panic(node_public_keys.committee_signing_key());
    let ni_dkg_dealing_encryption_pk =
        encode_or_panic(node_public_keys.dkg_dealing_encryption_key());
    let transport_tls_cert = encode_or_panic(node_public_keys.tls_certificate());
    let idkg_dealing_encryption_pk =
        encode_or_panic(node_public_keys.idkg_dealing_encryption_key());

    let payload = AddNodePayload {
        node_signing_pk,
        committee_signing_pk,
        ni_dkg_dealing_encryption_pk,
        transport_tls_cert,
        idkg_dealing_encryption_pk: Some(idkg_dealing_encryption_pk),
        xnet_endpoint: format!("128.0.{mutation_id}.1:1234"),
        http_endpoint: format!("128.0.{mutation_id}.1:4321"),
        p2p_flow_endpoints: vec![],
        prometheus_metrics_endpoint: "".to_string(),
        chip_id: None,
        public_ipv4_config: None,
        domain: None,
    };

    (payload, node_public_keys)
}
