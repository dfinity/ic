//! Integration tests for the engine controller canister.
//!
//! Boot up PocketIC, install the real registry canister bootstrapped with a
//! set of nodes and an invariant-compliant base state, install the
//! engine_controller canister at the canonical `ENGINE_CONTROLLER_CANISTER_ID`,
//! and exercise its public API end-to-end.
use candid::{Decode, Encode, Principal};
use canister_test::Project;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_engine_controller::{
    CreateEngineArgs, DeleteEngineArgs, EngineControllerInitArgs, NewSubnet,
};
use ic_management_canister_types::CanisterSettings;
use ic_nns_constants::{ENGINE_CONTROLLER_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_test_utils::common::build_registry_wasm;
use ic_nns_test_utils::registry::{
    INITIAL_MUTATION_ID, invariant_compliant_mutation_with_subnet_id, new_node_keys_and_node_id,
};
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::subnet::v1::{
    SubnetListRecord as SubnetListRecordPb, SubnetRecord as SubnetRecordPb, SubnetType,
};
use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_registry_transport::pb::v1::RegistryMutation;
use ic_registry_transport::pb::v1::high_capacity_registry_get_value_response::Content;
use ic_registry_transport::{deserialize_get_value_response, serialize_get_value_request};
use ic_types::ReplicaVersion;
use pocket_ic::PocketIcBuilder;
use pocket_ic::nonblocking::PocketIc;
use prost::Message;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use registry_canister::mutations::node_management::common::make_add_node_registry_mutations;
use registry_canister::mutations::node_management::do_add_node::connection_endpoint_from_string;
use std::convert::TryFrom;

// Must match the principal hard-coded in `engine_controller`.
const AUTHORIZED_CALLER: &str = "bct5z-vccu4-6q4t2-3lb6l-wm43p-ulppt-o5sqq-w6het-rthdz-qp4yn-fqe";

/// Replica version that the registry test fixtures have already elected.
fn test_replica_version() -> String {
    ReplicaVersion::default().to_string()
}

fn authorized() -> Principal {
    Principal::from_text(AUTHORIZED_CALLER).unwrap()
}

async fn install_at(
    pic: &PocketIc,
    canister_id: ic_base_types::CanisterId,
    wasm: Vec<u8>,
    arg: Vec<u8>,
    controller: Principal,
) {
    pic.create_canister_with_id(
        Some(controller),
        Some(CanisterSettings {
            controllers: Some(vec![controller]),
            ..Default::default()
        }),
        canister_id.into(),
    )
    .await
    .unwrap();
    pic.install_canister(canister_id.into(), wasm, arg, Some(controller))
        .await;
}

/// Build a mutation request that adds `n` nodes with valid keys to the registry.
fn prepare_nodes(n: u64, starting_mutation_id: u8) -> (RegistryAtomicMutateRequest, Vec<NodeId>) {
    let mut mutations = vec![];
    let mut node_ids = vec![];
    for i in 0..n {
        let (valid_pks, node_id) = new_node_keys_and_node_id();
        let effective_id = starting_mutation_id + (i as u8);
        let node_record = NodeRecord {
            node_operator_id: PrincipalId::new_user_test_id(999).into_vec(),
            xnet: Some(connection_endpoint_from_string(&format!(
                "128.0.{effective_id}.1:1234"
            ))),
            http: Some(connection_endpoint_from_string(&format!(
                "128.0.{effective_id}.1:4321"
            ))),
            node_reward_type: Some(i32::from(NodeRewardType::Type4)),
            ..Default::default()
        };
        mutations.append(&mut make_add_node_registry_mutations(
            node_id,
            node_record,
            valid_pks,
        ));
        node_ids.push(node_id);
    }
    (
        RegistryAtomicMutateRequest {
            mutations,
            preconditions: vec![],
        },
        node_ids,
    )
}

/// Returns PocketIC's actual NNS subnet id, so the registry's bootstrap
/// state can claim *that* subnet as the NNS and `initial_dkg_subnet_id`
/// resolution at create-subnet time routes to a real subnet.
async fn pocket_ic_nns_subnet_id(pic: &PocketIc) -> SubnetId {
    let topology = pic.topology().await;
    let nns = topology.get_nns().expect("pocket-ic has no NNS subnet");
    SubnetId::new(PrincipalId(nns))
}

fn invariant_compliant_mutation_as_atomic_req(
    mutation_id: u8,
    subnet_id: SubnetId,
) -> RegistryAtomicMutateRequest {
    RegistryAtomicMutateRequest {
        mutations: invariant_compliant_mutation_with_subnet_id(mutation_id, subnet_id, None)
            .into_iter()
            .collect::<Vec<RegistryMutation>>(),
        preconditions: vec![],
    }
}

async fn setup(num_nodes: u64) -> (PocketIc, Vec<NodeId>, SubnetId) {
    let pic = PocketIcBuilder::new().with_nns_subnet().build_async().await;
    let nns_subnet_id = pocket_ic_nns_subnet_id(&pic).await;

    let (init_mutate, node_ids) = prepare_nodes(num_nodes, INITIAL_MUTATION_ID);
    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(
        num_nodes as u8 + INITIAL_MUTATION_ID,
        nns_subnet_id,
    ));
    builder.push_init_mutate_request(init_mutate);

    install_at(
        &pic,
        REGISTRY_CANISTER_ID,
        build_registry_wasm().bytes(),
        Encode!(&builder.build()).unwrap(),
        ROOT_CANISTER_ID.get().0,
    )
    .await;

    let engine_controller_wasm =
        Project::cargo_bin_maybe_from_env("engine-controller-canister", &[]);
    install_at(
        &pic,
        ENGINE_CONTROLLER_CANISTER_ID,
        engine_controller_wasm.bytes(),
        Encode!(&Some(EngineControllerInitArgs {
            authorized_caller: None,
            initial_dkg_subnet_id: Some(nns_subnet_id.get().0),
        }))
        .unwrap(),
        ROOT_CANISTER_ID.into(),
    )
    .await;

    (pic, node_ids, nns_subnet_id)
}

async fn call_create_engine(
    pic: &PocketIc,
    sender: Principal,
    args: &CreateEngineArgs,
) -> Result<NewSubnet, String> {
    let raw = pic
        .update_call(
            ENGINE_CONTROLLER_CANISTER_ID.get().0,
            sender,
            "create_engine",
            Encode!(args).unwrap(),
        )
        .await
        .expect("ingress call should succeed");
    Decode!(&raw, Result<NewSubnet, String>).unwrap()
}

async fn call_delete_engine(
    pic: &PocketIc,
    sender: Principal,
    args: &DeleteEngineArgs,
) -> Result<(), String> {
    let raw = pic
        .update_call(
            ENGINE_CONTROLLER_CANISTER_ID.get().0,
            sender,
            "delete_engine",
            Encode!(args).unwrap(),
        )
        .await
        .expect("ingress call should succeed");
    Decode!(&raw, Result<(), String>).unwrap()
}

async fn registry_get_value(pic: &PocketIc, key: Vec<u8>) -> Vec<u8> {
    let request = serialize_get_value_request(key, None).unwrap();
    let raw = pic
        .query_call(
            REGISTRY_CANISTER_ID.get().0,
            Principal::anonymous(),
            "get_value",
            request,
        )
        .await
        .unwrap();
    let resp = deserialize_get_value_response(raw).expect("decode get_value response");
    match resp.content.expect("registry response had no content") {
        Content::Value(bytes) => bytes,
        Content::LargeValueChunkKeys(_) => panic!("unexpected large value chunk keys"),
    }
}

async fn subnet_list(pic: &PocketIc) -> Vec<Vec<u8>> {
    let bytes = registry_get_value(pic, make_subnet_list_record_key().as_bytes().to_vec()).await;
    SubnetListRecordPb::decode(bytes.as_slice())
        .unwrap()
        .subnets
}

fn node_principals(node_ids: &[NodeId]) -> Vec<Principal> {
    node_ids.iter().map(|n| n.get().0).collect()
}

#[tokio::test]
async fn create_engine_then_delete_engine_succeeds() {
    let (pic, node_ids, _nns_subnet_id) = setup(4).await;

    let initial_subnets = subnet_list(&pic).await;

    let create_args = CreateEngineArgs {
        node_ids: node_principals(&node_ids),
        subnet_admins: vec![],
        replica_version_id: test_replica_version(),
    };

    let new_subnet = call_create_engine(&pic, authorized(), &create_args)
        .await
        .expect("create_engine should succeed");
    let returned_subnet_id = new_subnet
        .new_subnet_id
        .expect("create_engine should return a new subnet id");

    let after_create = subnet_list(&pic).await;
    let new_subnets: Vec<_> = after_create
        .iter()
        .filter(|s| !initial_subnets.contains(s))
        .collect();
    assert_eq!(new_subnets.len(), 1, "exactly one new subnet must appear");
    let new_subnet_id = SubnetId::new(PrincipalId::try_from(new_subnets[0].as_slice()).unwrap());
    assert_eq!(
        returned_subnet_id, new_subnet_id,
        "returned subnet id must match the one in the registry"
    );

    // Verify the new subnet was registered as a CloudEngine.
    let raw = registry_get_value(
        &pic,
        make_subnet_record_key(new_subnet_id).as_bytes().to_vec(),
    )
    .await;
    let subnet_record = SubnetRecordPb::decode(raw.as_slice()).unwrap();
    assert_eq!(
        subnet_record.subnet_type,
        i32::from(SubnetType::CloudEngine)
    );

    // Delete the engine again.
    call_delete_engine(
        &pic,
        authorized(),
        &DeleteEngineArgs {
            subnet_id: new_subnet_id.get().0,
        },
    )
    .await
    .expect("delete_engine should succeed");

    let final_subnets = subnet_list(&pic).await;
    assert_eq!(final_subnets, initial_subnets);
}

#[tokio::test]
async fn create_engine_caller_must_be_authorized() {
    let (pic, node_ids, _nns_subnet_id) = setup(4).await;
    let attacker = Principal::self_authenticating(b"attacker");
    let args = CreateEngineArgs {
        node_ids: node_principals(&node_ids),
        subnet_admins: vec![],
        replica_version_id: test_replica_version(),
    };
    let err = call_create_engine(&pic, attacker, &args).await.unwrap_err();
    assert!(err.contains("not authorized"), "unexpected error: {err}");
}

#[tokio::test]
async fn create_engine_rejects_fewer_than_four_nodes() {
    let (pic, node_ids, _nns_subnet_id) = setup(5).await;
    let mut nodes = node_principals(&node_ids);
    nodes.truncate(3);
    let err = call_create_engine(
        &pic,
        authorized(),
        &CreateEngineArgs {
            node_ids: nodes,
            subnet_admins: vec![],
            replica_version_id: test_replica_version(),
        },
    )
    .await
    .unwrap_err();
    assert!(
        err.contains("Expected at least 4"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn create_engine_accepts_more_than_four_nodes() {
    let (pic, node_ids, _nns_subnet_id) = setup(7).await;
    assert_eq!(node_ids.len(), 7);
    let create_args = CreateEngineArgs {
        node_ids: node_principals(&node_ids),
        subnet_admins: vec![],
        replica_version_id: test_replica_version(),
    };

    let initial_subnets = subnet_list(&pic).await;
    call_create_engine(&pic, authorized(), &create_args)
        .await
        .expect("create_engine should accept >4 nodes");

    let after = subnet_list(&pic).await;
    let new_subnets: Vec<_> = after
        .iter()
        .filter(|s| !initial_subnets.contains(s))
        .collect();
    assert_eq!(new_subnets.len(), 1, "exactly one new subnet must appear");
}

#[tokio::test]
async fn create_engine_rejects_duplicates() {
    let (pic, node_ids, _nns_subnet_id) = setup(4).await;
    let mut nodes = node_principals(&node_ids);
    nodes[1] = nodes[0];
    let err = call_create_engine(
        &pic,
        authorized(),
        &CreateEngineArgs {
            node_ids: nodes,
            subnet_admins: vec![],
            replica_version_id: test_replica_version(),
        },
    )
    .await
    .unwrap_err();
    assert!(err.contains("Duplicate node id"), "unexpected error: {err}");
}

#[tokio::test]
async fn init_arg_overrides_authorized_caller_and_survives_upgrade() {
    let custom_caller = Principal::self_authenticating(b"custom-caller");
    let pic = PocketIcBuilder::new().with_nns_subnet().build_async().await;
    let nns_subnet_id = pocket_ic_nns_subnet_id(&pic).await;

    // Bootstrap the registry with 4 nodes so create_engine has something to work with.
    let (init_mutate, node_ids) = prepare_nodes(4, INITIAL_MUTATION_ID);
    let mut builder = RegistryCanisterInitPayloadBuilder::new();
    builder.push_init_mutate_request(invariant_compliant_mutation_as_atomic_req(
        4 + INITIAL_MUTATION_ID,
        nns_subnet_id,
    ));
    builder.push_init_mutate_request(init_mutate);
    install_at(
        &pic,
        REGISTRY_CANISTER_ID,
        build_registry_wasm().bytes(),
        Encode!(&builder.build()).unwrap(),
        ROOT_CANISTER_ID.get().0,
    )
    .await;

    // Install with a custom authorized caller.
    let wasm = Project::cargo_bin_maybe_from_env("engine-controller-canister", &[]);
    install_at(
        &pic,
        ENGINE_CONTROLLER_CANISTER_ID,
        wasm.clone().bytes(),
        Encode!(&Some(EngineControllerInitArgs {
            authorized_caller: Some(custom_caller),
            initial_dkg_subnet_id: Some(nns_subnet_id.get().0),
        }))
        .unwrap(),
        Principal::anonymous(),
    )
    .await;

    // The hardcoded default principal must now be rejected.
    let args = CreateEngineArgs {
        node_ids: node_principals(&node_ids),
        subnet_admins: vec![],
        replica_version_id: test_replica_version(),
    };
    let err = call_create_engine(&pic, authorized(), &args)
        .await
        .unwrap_err();
    assert!(err.contains("not authorized"), "unexpected error: {err}");

    // The custom principal must be accepted.
    call_create_engine(&pic, custom_caller, &args)
        .await
        .expect("custom caller should be authorized after init");

    // Upgrade with no override: default principal becomes authorized again.
    pic.upgrade_canister(
        ENGINE_CONTROLLER_CANISTER_ID.into(),
        wasm.bytes(),
        Encode!(&None::<EngineControllerInitArgs>).unwrap(),
        Some(Principal::anonymous()),
    )
    .await
    .expect("upgrade should succeed");

    let err = call_create_engine(&pic, custom_caller, &args)
        .await
        .unwrap_err();
    assert!(
        err.contains("not authorized"),
        "custom caller must be rejected after upgrade with default: {err}"
    );
}

#[tokio::test]
async fn delete_engine_caller_must_be_authorized() {
    let (pic, _, _) = setup(4).await;
    let attacker = Principal::self_authenticating(b"attacker");
    let err = call_delete_engine(
        &pic,
        attacker,
        &DeleteEngineArgs {
            subnet_id: Principal::management_canister(),
        },
    )
    .await
    .unwrap_err();
    assert!(err.contains("not authorized"), "unexpected error: {err}");
}
