use std::{collections::BTreeMap, path::PathBuf};

use candid::Principal;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_handler_root::backup_root_proposals::ChangeSubnetHaltStatus;
use ic_protobuf::registry::{
    replica_version::v1::{BlessedReplicaVersions, ReplicaVersionRecord},
    routing_table::v1::RoutingTable as RoutingTablePB,
    subnet::v1::SubnetListRecord,
};
use ic_registry_keys::{
    make_blessed_replica_versions_key, make_replica_version_key, make_routing_table_record_key,
};
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{
    insert,
    pb::v1::{RegistryAtomicMutateRequest, RegistryMutation},
};
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

fn add_replica_version_records(total_mutations: &mut Vec<RegistryMutation>) {
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
}

fn add_routing_table_record(total_mutations: &mut Vec<RegistryMutation>, nns_id: PrincipalId) {
    let routing_table = RoutingTable::try_from(btreemap! {
        CanisterIdRange {
           start: CanisterId::from(0),
           end: CanisterId::from(u64::MAX),
        } => SubnetId::new(nns_id),
    })
    .unwrap();
    total_mutations.push(insert(
        make_routing_table_record_key().as_bytes(),
        RoutingTablePB::from(routing_table).encode_to_vec(),
    ));
}

struct SubnetNodeOperatorArg {
    subnet_id: PrincipalId,
    subnet_type: SubnetType,
    node_operators: Vec<PrincipalId>,
}

struct RegistryPreparationArguments {
    subnet_node_operators: Vec<SubnetNodeOperatorArg>,
}

fn prepare_registry(
    registry_preparation_args: &mut RegistryPreparationArguments,
) -> Vec<RegistryAtomicMutateRequest> {
    // let nns_id: SubnetId = SubnetId::from(PrincipalId(nns_id));
    // let app_id: SubnetId = SubnetId::from(PrincipalId(app_id));
    let mut total_mutations = vec![];
    let mut subnet_list_record = SubnetListRecord::default();

    add_replica_version_records(&mut total_mutations);

    let mut operator_mutation_ids: u8 = 0;
    for arg in &registry_preparation_args.subnet_node_operators {
        let mut current_subnet_nodes = BTreeMap::new();
        for operator in &arg.node_operators {
            let (mutation, nodes) = prepare_registry_with_nodes_and_node_operator_id(
                operator_mutation_ids * 4,
                4,
                operator.clone(),
            );
            operator_mutation_ids += 1;

            total_mutations.extend(mutation.mutations);
            current_subnet_nodes.extend(nodes);
        }

        let mutations = add_fake_subnet(
            arg.subnet_id.into(),
            &mut subnet_list_record,
            get_invariant_compliant_subnet_record(
                current_subnet_nodes.keys().cloned().collect(),
                arg.subnet_type,
            ),
            &current_subnet_nodes,
        );
        total_mutations.extend(mutations);
    }

    add_routing_table_record(
        &mut total_mutations,
        registry_preparation_args
            .subnet_node_operators
            .iter()
            .find_map(|arg| match arg.subnet_type {
                SubnetType::System => Some(arg.subnet_id.clone()),
                _ => None,
            })
            .expect("Missing system subnet"),
    );

    vec![RegistryAtomicMutateRequest {
        mutations: total_mutations,
        ..Default::default()
    }]
}

fn init_pocket_ic(arguments: &mut RegistryPreparationArguments) -> (PocketIc, Principal) {
    let mut builder = PocketIcBuilder::new();

    for arg in &arguments.subnet_node_operators {
        if arg.subnet_type == SubnetType::System {
            builder = builder.with_nns_subnet();
            continue;
        }

        builder = builder.with_application_subnet();
    }

    let pic = builder.build();
    let nns = pic.topology().get_nns().expect("Should contain nns");
    let arg_nns = arguments
        .subnet_node_operators
        .iter_mut()
        .find(|arg| arg.subnet_type == SubnetType::System)
        .unwrap();
    arg_nns.subnet_id = nns.into();

    for (arg, subnet_id) in arguments
        .subnet_node_operators
        .iter_mut()
        .filter(|arg| arg.subnet_type == SubnetType::Application)
        .zip(pic.topology().get_app_subnets())
    {
        arg.subnet_id = subnet_id.into()
    }

    let registry = pic
        .create_canister_with_id(None, None, REGISTRY_CANISTER_ID.into())
        .unwrap();
    pic.add_cycles(registry, 100_000_000_000_000);

    pic.install_canister(
        registry,
        fetch_canister_wasm("REGISTRY_WASM_PATH"),
        candid::encode_one(RegistryCanisterInitPayload {
            mutations: prepare_registry(arguments),
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

#[test]
fn fetch_pending_proposals_submited_one() {
    let mut args = RegistryPreparationArguments {
        subnet_node_operators: vec![
            SubnetNodeOperatorArg {
                subnet_id: PrincipalId::new_subnet_test_id(0),
                subnet_type: SubnetType::System,
                node_operators: vec![
                    // Each has 4 nodes so this is 40 nodes in total
                    PrincipalId::new_user_test_id(0),
                    PrincipalId::new_user_test_id(1),
                    PrincipalId::new_user_test_id(2),
                    PrincipalId::new_user_test_id(3),
                    PrincipalId::new_user_test_id(4),
                    PrincipalId::new_user_test_id(5),
                    PrincipalId::new_user_test_id(6),
                    PrincipalId::new_user_test_id(7),
                    PrincipalId::new_user_test_id(8),
                    PrincipalId::new_user_test_id(9),
                ],
            },
            SubnetNodeOperatorArg {
                subnet_id: PrincipalId::new_subnet_test_id(0),
                subnet_type: SubnetType::Application,
                node_operators: vec![PrincipalId::new_user_test_id(999)],
            },
        ],
    };
    let (pic, canister) = init_pocket_ic(&mut args);

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
