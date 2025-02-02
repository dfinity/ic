use std::{collections::BTreeMap, path::PathBuf};

use candid::Principal;
use ic_base_types::{CanisterId, NodeId, PrincipalId, SubnetId};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_handler_root::backup_root_proposals::ChangeSubnetHaltStatus;
use ic_protobuf::registry::{
    crypto::v1::PublicKey,
    replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    routing_table::v1::RoutingTable as RoutingTablePB,
    subnet::v1::SubnetListRecord,
};
use ic_registry_keys::{
    make_blessed_replica_versions_key, make_replica_version_key, make_routing_table_record_key,
};
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_transport::{insert, pb::v1::RegistryAtomicMutateRequest};
use maplit::btreemap;
use pocket_ic::{PocketIc, PocketIcBuilder};
use prost::Message;
use registry_canister::init::RegistryCanisterInitPayload;
use test_helpers::{
    add_fake_subnet, get_invariant_compliant_subnet_record,
    prepare_registry_with_nodes_and_node_operator_id,
};

mod test_helpers;

fn fetch_canister_wasm(env: &str) -> Vec<u8> {
    let path: PathBuf = std::env::var(env)
        .expect(&format!("Path should be set in environment variable {env}"))
        .try_into()
        .unwrap();
    std::fs::read(&path).expect(&format!("Failed to read path {}", path.display()))
}

fn prepare_registry(nns_id: Principal, app_id: Principal) -> Vec<RegistryAtomicMutateRequest> {
    let nns_id: SubnetId = SubnetId::from(PrincipalId(nns_id));
    let app_id: SubnetId = SubnetId::from(PrincipalId(app_id));
    let mut total_mutations = vec![];
    let mut operators_with_nodes = BTreeMap::new();

    const MOCK_HASH: &str = "d1bc8d3ba4afc7e109612cb73acbdddac052c93025aa1f82942edabb7deb82a1";
    let release_package_url = "http://release_package.tar.zst".to_string();
    let replica_version = insert(
        make_replica_version_key(env!("CARGO_PKG_VERSION")).as_bytes(),
        ReplicaVersionRecord {
            release_package_sha256_hex: MOCK_HASH.into(),
            release_package_urls: vec![release_package_url],
            guest_launch_measurement_sha256_hex: None,
        }
        .encode_to_vec(),
    );
    total_mutations.push(replica_version);
    let blessed_replica_versions = insert(
        make_blessed_replica_versions_key().as_bytes(),
        BlessedReplicaVersions {
            blessed_version_ids: vec![env!("CARGO_PKG_VERSION").to_string()],
        }
        .encode_to_vec(),
    );
    total_mutations.push(blessed_replica_versions);

    for no in 0..11 {
        let no_principal = PrincipalId::new_user_test_id(total_mutations.len() as u64);
        let (mutation, no_nodes) =
            prepare_registry_with_nodes_and_node_operator_id(no * 4, 4, no_principal.clone());

        operators_with_nodes.insert(no_principal, no_nodes);
        total_mutations.extend(mutation.mutations);
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

    let mutations = add_fake_subnet(
        nns_id,
        &mut subnet_list_record,
        get_invariant_compliant_subnet_record(
            nns_nodes.keys().cloned().collect(),
            ic_registry_subnet_type::SubnetType::System,
        ),
        &nns_nodes,
    );
    total_mutations.extend(mutations);

    let app_nodes: BTreeMap<NodeId, PublicKey> = operators_with_nodes
        .values()
        .skip(10)
        .take(1)
        .fold(BTreeMap::new(), |mut acc, next| {
            acc.extend(next.clone());
            acc
        });

    let mutations = add_fake_subnet(
        app_id,
        &mut subnet_list_record,
        get_invariant_compliant_subnet_record(
            app_nodes.keys().cloned().collect(),
            ic_registry_subnet_type::SubnetType::Application,
        ),
        &app_nodes,
    );
    total_mutations.extend(mutations);

    let routing_table = RoutingTable::try_from(btreemap! {
        CanisterIdRange {
           start: CanisterId::from(0),
           end: CanisterId::from(u64::MAX),
        } => nns_id,
    })
    .unwrap();
    total_mutations.push(insert(
        make_routing_table_record_key().as_bytes(),
        RoutingTablePB::from(routing_table).encode_to_vec(),
    ));

    vec![RegistryAtomicMutateRequest {
        mutations: total_mutations,
        ..Default::default()
    }]
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

    let nns_id = pic.topology().get_nns().unwrap();
    let app_subnets = pic.topology().get_app_subnets();
    pic.install_canister(
        registry,
        fetch_canister_wasm("REGISTRY_WASM_PATH"),
        candid::encode_one(RegistryCanisterInitPayload {
            mutations: prepare_registry(nns_id, app_subnets.first().unwrap().clone()),
        })
        .unwrap(),
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
