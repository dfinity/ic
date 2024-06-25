#![allow(dead_code)]

use candid::Encode;
use canister_test::{Canister, Runtime};
use ic_base_types::{NodeId, PrincipalId, RegistryVersion, SubnetId};
use ic_crypto_node_key_validation::ValidNodePublicKeys;
use ic_management_canister_types::{
    DerivationPath, ECDSAPublicKeyArgs, EcdsaKeyId, MasterPublicKeyId, Method as Ic00Method,
    SchnorrKeyId, SchnorrPublicKeyArgs,
};
use ic_nns_test_utils::itest_helpers::{
    set_up_registry_canister, set_up_universal_canister, try_call_via_universal_canister,
};
use ic_nns_test_utils::registry::{get_value_or_panic, new_node_keys_and_node_id};
use ic_protobuf::registry::node::v1::NodeRecord;
use ic_protobuf::registry::routing_table::v1 as pb;
use ic_protobuf::registry::subnet::v1::{
    CatchUpPackageContents, ChainKeyConfig as ChainKeyConfigPb, SubnetListRecord, SubnetRecord,
};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_features::{
    ChainKeyConfig, EcdsaConfig, KeyConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE,
};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_types::ReplicaVersion;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use registry_canister::mutations::do_create_subnet::CreateSubnetPayload;
use registry_canister::mutations::node_management::common::make_add_node_registry_mutations;
use registry_canister::mutations::node_management::do_add_node::connection_endpoint_from_string;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Duration;

// Test helpers
pub async fn get_subnet_list_record(registry: &Canister<'_>) -> SubnetListRecord {
    get_value_or_panic::<SubnetListRecord>(registry, make_subnet_list_record_key().as_bytes()).await
}

pub async fn get_subnet_record(registry: &Canister<'_>, subnet_id: SubnetId) -> SubnetRecord {
    get_value_or_panic::<SubnetRecord>(registry, make_subnet_record_key(subnet_id).as_bytes()).await
}

pub fn get_subnet_holding_ecdsa_keys(
    ecdsa_key_ids: &[EcdsaKeyId],
    node_ids: Vec<NodeId>,
) -> SubnetRecord {
    let mut record: SubnetRecord = CreateSubnetPayload {
        unit_delay_millis: 10,
        replica_version_id: ReplicaVersion::default().into(),
        node_ids,
        ..Default::default()
    }
    .into();

    let ecdsa_config = EcdsaConfig {
        quadruples_to_create_in_advance: 1,
        key_ids: ecdsa_key_ids.to_vec(),
        max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
        signature_request_timeout_ns: None,
        idkg_key_rotation_period_ms: None,
    };
    record.chain_key_config = Some(ChainKeyConfig::from(ecdsa_config.clone()).into());
    record.ecdsa_config = Some(ecdsa_config.into());

    record
}

pub fn get_subnet_holding_chain_keys(
    key_ids: Vec<MasterPublicKeyId>,
    node_ids: Vec<NodeId>,
) -> SubnetRecord {
    let unit_delay_millis = 10;
    let replica_version_id = String::from(ReplicaVersion::default());
    let mut subnet_record = SubnetRecord::from(CreateSubnetPayload {
        unit_delay_millis,
        replica_version_id,
        node_ids,
        ..Default::default()
    });
    subnet_record.chain_key_config = Some(ChainKeyConfigPb::from(ChainKeyConfig {
        key_configs: key_ids
            .into_iter()
            .map(|key_id| KeyConfig {
                key_id,
                pre_signatures_to_create_in_advance: 1,
                max_queue_size: DEFAULT_ECDSA_MAX_QUEUE_SIZE,
            })
            .collect(),
        signature_request_timeout_ns: None,
        idkg_key_rotation_period_ms: None,
    }));

    subnet_record
}

/// This allows us to create a registry canister that is in-sync with the FakeRegistryClient
/// and ProtoRegistryDataProvider used by the underlying IC setup (consensus and execution)
/// Without those being in sync, calls to CanisterId::ic_00 time out waiting for registry versions
/// to get in sync
pub async fn setup_registry_synced_with_fake_client(
    runtime: &'_ Runtime,
    fake_registry_client: Arc<FakeRegistryClient>,
    fake_data_provider: Arc<ProtoRegistryDataProvider>,
    initial_mutations: Vec<RegistryAtomicMutateRequest>,
) -> Canister<'_> {
    let initial_fake_data = fake_data_provider.export_versions_as_atomic_mutation_requests();
    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    for version in initial_fake_data {
        builder.push_init_mutate_request(version);
    }

    for m in initial_mutations {
        let next_version = RegistryVersion::from(fake_data_provider.latest_version().get() + 1);
        fake_data_provider.apply_mutations_as_version(m.mutations.clone(), next_version);
        builder.push_init_mutate_request(m);
    }
    fake_registry_client.update_to_latest_version();

    set_up_registry_canister(runtime, builder.build()).await
}

/// Prepare a mutate request to add the desired number of nodes, and returned the IDs
/// of the nodes to be added.
///
/// The argument `starting_mutation_id` can be used to avoid mutation collisions in tests
/// that involve multiple registry mutations, e.g., creating multiple node records that
/// should have distinct API endpoints.
///
/// This function will create `node_count` mutations.
///
/// Example usage:
/// ```
/// // Creates one initial mutation
/// let mut registry = registry_canister::common::test_helpers::invariant_compliant_registry(0);
/// // Creates 10 more mutations, so we have 11 mutations (0..10 inclusive).
/// let (mut_req_a, _) = prepare_registry_with_nodes(10, 1);
/// registry.maybe_apply_mutation_internal(mut_req_a.mutations)
/// // Creates 8 more mutations, so we have 19 mutations (0..18 inclusive).
/// let (mut_req_b, _) prepare_registry_with_nodes(8, 11);
/// registry.maybe_apply_mutation_internal(mut_req_b.mutations)
/// ```
pub fn prepare_registry_with_nodes(
    node_count: u64,
    starting_mutation_id: u8,
) -> (RegistryAtomicMutateRequest, Vec<NodeId>) {
    let (mutate_request, node_ids_and_valid_pks) =
        prepare_registry_with_nodes_and_valid_pks(node_count, starting_mutation_id);
    (
        mutate_request,
        node_ids_and_valid_pks.keys().cloned().collect(),
    )
}

/// Same as [`prepare_registry_with_nodes_and_valid_pks`], but also return the valid node public
/// keys.
pub fn prepare_registry_with_nodes_and_valid_pks(
    node_count: u64,
    starting_mutation_id: u8,
) -> (
    RegistryAtomicMutateRequest,
    BTreeMap<NodeId, ValidNodePublicKeys>,
) {
    let default_template = NodeRecord {
        node_operator_id: PrincipalId::new_user_test_id(999).into_vec(),
        ..Default::default()
    };

    prepare_registry_with_nodes_from_template(node_count, starting_mutation_id, default_template)
}

/// Following the same as `prepare_registry_with_nodes`, and additionally allow
/// passing a "template" used to fill values on each `NodeRecord`.
pub fn prepare_registry_with_nodes_from_template(
    node_count: u64,
    starting_mutation_id: u8,
    node_template: NodeRecord,
) -> (
    RegistryAtomicMutateRequest,
    BTreeMap<NodeId, ValidNodePublicKeys>,
) {
    // Prepare a transaction to add the nodes to the registry
    let mut mutations = vec![];
    let node_ids_and_valid_pks: BTreeMap<NodeId, ValidNodePublicKeys> = (0..node_count)
        .map(|id| {
            let (valid_pks, node_id) = new_node_keys_and_node_id();
            let effective_id = starting_mutation_id + (id as u8);
            let node_record = NodeRecord {
                xnet: Some(connection_endpoint_from_string(&format!(
                    "128.0.{effective_id}.1:1234"
                ))),
                http: Some(connection_endpoint_from_string(&format!(
                    "128.0.{effective_id}.1:4321"
                ))),
                ..node_template.clone()
            };
            mutations.append(&mut make_add_node_registry_mutations(
                node_id,
                node_record,
                valid_pks.clone(),
            ));
            (node_id, valid_pks)
        })
        .collect();

    let mutate_request = RegistryAtomicMutateRequest {
        mutations,
        preconditions: vec![],
    };

    (mutate_request, node_ids_and_valid_pks)
}

fn get_added_subnets(
    former_subnet_list_record: &SubnetListRecord,
    current_subnet_list_record: &SubnetListRecord,
) -> Vec<SubnetId> {
    current_subnet_list_record
        .subnets
        .iter()
        .filter(|&x| !former_subnet_list_record.subnets.contains(x))
        .map(|s| SubnetId::new(PrincipalId::try_from(s.clone().as_slice()).unwrap()))
        .collect()
}

// This does not do anything special - just ensures you created the canister in the right position
// so that it gets the governance ID
pub async fn set_up_universal_canister_as_governance(runtime: &'_ Runtime) -> Canister<'_> {
    // Install the universal canister in place of the governance canister
    let fake_governance_canister = set_up_universal_canister(runtime).await;
    // Since it takes the id reserved for the governance canister, it can impersonate
    // it
    assert_eq!(
        fake_governance_canister.canister_id(),
        ic_nns_constants::GOVERNANCE_CANISTER_ID
    );
    fake_governance_canister
}

pub async fn get_added_subnet(
    registry: &Canister<'_>,
    former_subnet_list_record: &SubnetListRecord,
) -> (SubnetId, SubnetRecord) {
    let subnet_list_record = get_subnet_list_record(registry).await;

    let added_subnet_ids = get_added_subnets(former_subnet_list_record, &subnet_list_record);
    // ensure only one subnet was added, or this function won't give expected results
    assert_eq!(added_subnet_ids.len(), 1);
    let subnet_id = added_subnet_ids[0_usize];
    (subnet_id, get_subnet_record(registry, subnet_id).await)
}

pub async fn get_cup_contents(
    registry: &Canister<'_>,
    subnet_id: SubnetId,
) -> CatchUpPackageContents {
    get_value_or_panic::<CatchUpPackageContents>(
        registry,
        make_catch_up_package_contents_key(subnet_id).as_bytes(),
    )
    .await
}

/// Requests an ECDSA public key several times until it succeeds.
pub async fn wait_for_ecdsa_setup(
    runtime: &Runtime,
    calling_canister: &Canister<'_>,
    key_id: &EcdsaKeyId,
) {
    let public_key_request = ECDSAPublicKeyArgs {
        canister_id: None,
        derivation_path: DerivationPath::new(vec![]),
        key_id: key_id.clone(),
    };
    let mut public_key_result = None;
    for i in 0..100 {
        public_key_result = Some(
            try_call_via_universal_canister(
                calling_canister,
                &runtime.get_management_canister_with_effective_canister_id(
                    calling_canister.canister_id().into(),
                ),
                &Ic00Method::ECDSAPublicKey.to_string(),
                Encode!(&public_key_request).unwrap(),
            )
            .await,
        );
        println!("Response: {:?}", public_key_result);
        if public_key_result.as_ref().unwrap().is_ok() {
            break;
        }
        println!("Waiting for public key... {}", i);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    public_key_result.unwrap().unwrap();
}

/// Requests a Schnorr public key several times until it succeeds.
pub async fn wait_for_schnorr_setup(
    runtime: &Runtime,
    calling_canister: &Canister<'_>,
    key_id: &SchnorrKeyId,
) {
    let public_key_request = SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path: DerivationPath::new(vec![]),
        key_id: key_id.clone(),
    };
    let mut public_key_result = None;
    for i in 0..100 {
        public_key_result = Some(
            try_call_via_universal_canister(
                calling_canister,
                &runtime.get_management_canister_with_effective_canister_id(
                    calling_canister.canister_id().into(),
                ),
                &Ic00Method::SchnorrPublicKey.to_string(),
                Encode!(&public_key_request).unwrap(),
            )
            .await,
        );
        println!("Response: {:?}", public_key_result);
        if public_key_result.as_ref().unwrap().is_ok() {
            break;
        }
        println!("Waiting for public key... {}", i);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    public_key_result.unwrap().unwrap();
}

pub async fn wait_for_chain_key_setup(
    runtime: &Runtime,
    calling_canister: &Canister<'_>,
    master_public_key_id: &MasterPublicKeyId,
) {
    match master_public_key_id {
        MasterPublicKeyId::Ecdsa(key_id) => {
            wait_for_ecdsa_setup(runtime, calling_canister, key_id).await;
        }
        MasterPublicKeyId::Schnorr(key_id) => {
            wait_for_schnorr_setup(runtime, calling_canister, key_id).await;
        }
    }
}

pub fn check_error_message<T: std::fmt::Debug>(
    result: Result<T, String>,
    expected_substring: &str,
) {
    match result {
        Ok(value) => panic!(
            "expected the call to fail with message '{}', got Ok({:?})",
            expected_substring, value
        ),
        Err(e) => assert!(
            e.contains(expected_substring),
            "expected the call to fail with message '{}', got:  {}",
            expected_substring,
            e
        ),
    }
}

pub async fn get_routing_table(canister: &canister_test::Canister<'_>) -> RoutingTable {
    let pb_routing_table: pb::RoutingTable = get_value_or_panic(canister, b"routing_table").await;
    RoutingTable::try_from(pb_routing_table).expect("failed to decode routing table")
}
