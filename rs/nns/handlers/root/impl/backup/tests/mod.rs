use std::{collections::BTreeMap, path::PathBuf};

use candid::Principal;
use ic_base_types::{NodeId, PrincipalId};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_handler_root::backup_root_proposals::ChangeSubnetHaltStatus;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_types::crypto::canister_threshold_sig::PublicKey;
use pocket_ic::{PocketIc, PocketIcBuilder};
use registry_canister::{
    // common::test_helpers::{
    //     add_fake_subnet, get_invariant_compliant_subnet_record,
    //     prepare_registry_with_nodes_and_node_operator_id,
    // },
    init::RegistryCanisterInitPayload,
};

fn fetch_canister_wasm(env: &str) -> Vec<u8> {
    let path: PathBuf = std::env::var(env)
        .expect(&format!("Path should be set in environment variable {env}"))
        .try_into()
        .unwrap();
    std::fs::read(&path).expect(&format!("Failed to read path {}", path.display()))
}

fn prepare_registry(nns_id: PrincipalId, app_id: PrincipalId) -> Vec<RegistryAtomicMutateRequest> {
    let mut total_mutations = vec![];
    let mut operators_with_nodes = BTreeMap::new();

    for no in 0..11 {
        let no_principal = PrincipalId::new_user_test_id(total_mutations.len() as u64);
        let (mutation, no_nodes): (RegistryAtomicMutateRequest, BTreeMap<NodeId, PublicKey>) =
            (RegistryAtomicMutateRequest::default(), BTreeMap::new());
        // prepare_registry_with_nodes_and_node_operator_id(no, 4, no_principal.clone());

        operators_with_nodes.insert(no_principal, no_nodes);
        total_mutations.push(mutation);
    }

    // First 40 nodes goes to nns => 10 node operators * 4 nodes each
    let mut subnet_list_record = SubnetListRecord::default();
    let nns_nodes: BTreeMap<NodeId, PublicKey> =
        operators_with_nodes
            .values()
            .take(10)
            .fold(BTreeMap::new(), |mut acc, next| {
                acc.extend(next.clone());
                acc
            });

    // add_fake_subnet(
    //     nns_id,
    //     &mut subnet_list_record,
    //     get_invariant_compliant_subnet_record(nns_nodes.keys().cloned().collect()),
    //     &nns_nodes,
    // );

    total_mutations
}

fn init_pocket_ic() -> (PocketIc, Principal) {
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_nns_subnet()
        .build();
    let registry = pic
        .create_canister_with_id(None, None, REGISTRY_CANISTER_ID.into())
        .unwrap();
    pic.add_cycles(registry, 100_000_000_000_000);

    pic.install_canister(
        registry,
        fetch_canister_wasm("REGISTRY_WASM_PATH"),
        candid::encode_one(RegistryCanisterInitPayload { mutations: vec![] }).unwrap(),
        None,
    );

    let app_subnets = pic.topology().get_app_subnets();

    let subnet_id = app_subnets.first().expect("Should contain one app subnet");

    let canister = pic.create_canister_on_subnet(None, None, *subnet_id);
    pic.add_cycles(canister, 100_000_000_000_000);
    pic.install_canister(
        canister,
        fetch_canister_wasm("BACKUP_ROOT_WASM_PATH"),
        candid::encode_one(()).unwrap(),
        None,
    );
    (pic, canister)
}

// #[test]
fn fetch_pending_proposals_empty() {
    let (pic, canister) = init_pocket_ic();
    let response = pic
        .update_call(
            canister,
            Principal::anonymous(),
            "get_pending_root_proposals_to_change_subnet_halt_status",
            candid::encode_one(()).unwrap(),
        )
        .expect("Should be able to fetch pending root proposals to upgrade governance canister");

    let response: Vec<ChangeSubnetHaltStatus> =
        candid::decode_one(&response).expect("Should be able to decode response");

    assert!(response.is_empty())
}

#[test]
fn fetch_pending_proposals_submited_one() {
    let (pic, canister) = init_pocket_ic();

    let subnet_id = pic.get_subnet(canister).unwrap();

    let response = pic.update_call(
        canister,
        Principal::anonymous(),
        "submit_root_proposal_to_change_subnet_halt_status",
        candid::encode_args((subnet_id, true)).unwrap(),
    );
    let response: Result<(), String> = candid::decode_one(response.unwrap().as_slice()).unwrap();
    println!("{:?}", response);

    assert!(response.is_ok());

    let response = pic
        .update_call(
            canister,
            Principal::anonymous(),
            "get_pending_root_proposals_to_change_subnet_halt_status",
            candid::encode_one(()).unwrap(),
        )
        .expect("Should be able to fetch remaining proposals");

    let response: Vec<ChangeSubnetHaltStatus> =
        candid::decode_one(&response).expect("Should be able to decode response");

    assert!(response.len() == 1)
}
