use std::{collections::BTreeMap, path::PathBuf};

use candid::Principal;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_nns_constants::REGISTRY_CANISTER_ID;
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
    // Operator id : number of nodes in subnet
    node_operators: BTreeMap<PrincipalId, u8>,
}

struct RegistryPreparationArguments {
    subnet_node_operators: Vec<SubnetNodeOperatorArg>,
}

impl Default for RegistryPreparationArguments {
    fn default() -> Self {
        Self {
            subnet_node_operators: vec![
                SubnetNodeOperatorArg {
                    subnet_id: PrincipalId::new_subnet_test_id(0),
                    subnet_type: SubnetType::System,
                    node_operators: vec![
                        // Each has 4 nodes so this is 40 nodes in total
                        (PrincipalId::new_user_test_id(0), 4),
                        (PrincipalId::new_user_test_id(1), 4),
                        (PrincipalId::new_user_test_id(2), 4),
                        (PrincipalId::new_user_test_id(3), 4),
                        (PrincipalId::new_user_test_id(4), 4),
                        (PrincipalId::new_user_test_id(5), 4),
                        (PrincipalId::new_user_test_id(6), 4),
                        (PrincipalId::new_user_test_id(7), 4),
                        (PrincipalId::new_user_test_id(8), 4),
                        (PrincipalId::new_user_test_id(9), 4),
                    ]
                    .into_iter()
                    .collect(),
                },
                SubnetNodeOperatorArg {
                    subnet_id: PrincipalId::new_subnet_test_id(0),
                    subnet_type: SubnetType::Application,
                    node_operators: vec![(PrincipalId::new_user_test_id(999), 4)]
                        .into_iter()
                        .collect(),
                },
            ],
        }
    }
}

fn prepare_registry(
    registry_preparation_args: &mut RegistryPreparationArguments,
) -> Vec<RegistryAtomicMutateRequest> {
    let mut total_mutations = vec![];
    let mut subnet_list_record = SubnetListRecord::default();

    add_replica_version_records(&mut total_mutations);

    let mut operator_mutation_ids: u8 = 0;
    for arg in &registry_preparation_args.subnet_node_operators {
        let mut current_subnet_nodes = BTreeMap::new();
        for (operator, num_nodes) in &arg.node_operators {
            let (mutation, nodes) = prepare_registry_with_nodes_and_node_operator_id(
                operator_mutation_ids,
                *num_nodes as u64,
                operator.clone(),
            );
            operator_mutation_ids += num_nodes;

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

fn submit_proposal(
    pic: &PocketIc,
    canister: Principal,
    sender: Principal,
    subnet_id: Principal,
    to_halt: bool,
) -> Result<(), String> {
    let response = pic.update_call(
        canister.into(),
        sender,
        "submit_root_proposal_to_change_subnet_halt_status",
        candid::encode_args((subnet_id, to_halt)).unwrap(),
    );
    let response: Result<(), String> = candid::decode_one(response.unwrap().as_slice()).unwrap();
    println!("{:?}", response);
    response
}

fn get_pending(pic: &PocketIc, canister: Principal) -> Vec<u8> {
    let response = pic
        .update_call(
            canister.into(),
            Principal::anonymous(),
            "get_pending_root_proposals_to_change_subnet_halt_status",
            candid::encode_one(()).unwrap(),
        )
        .expect("Should be able to fetch remaining proposals");

    let response: Vec<u8> =
        candid::decode_one(&response).expect("Should be able to decode response");
    println!("{:?}", response);

    response
}

fn vote(
    pic: &PocketIc,
    canister: Principal,
    sender: Principal,
    proposer: PrincipalId,
    ballot: u8,
) -> Result<(), String> {
    let response = pic
        .update_call(
            canister.into(),
            sender,
            "vote_on_root_proposal_to_change_subnet_halt_status",
            candid::encode_args((proposer, ballot)).unwrap(),
        )
        .expect("Should be able to call vote function");

    let response: Result<(), String> =
        candid::decode_one(&response).expect("Should be able to decode response");
    println!("{:?}", response);
    response
}

// #[test]
// fn fetch_pending_proposals_submited_one() {
//     let mut args = RegistryPreparationArguments::default();
//     let (pic, canister) = init_pocket_ic(&mut args);

//     let nns = pic.topology().get_nns().unwrap();
//     let no_in_subnet = args
//         .subnet_node_operators
//         .iter()
//         .find_map(|arg| match arg.subnet_id.0 == nns {
//             true => {
//                 let operator_principals = arg
//                     .node_operators
//                     .iter()
//                     .map(|(principal, _)| principal)
//                     .collect::<Vec<_>>();

//                 operator_principals.first().cloned()
//             }
//             false => None,
//         })
//         .expect("Should be able to find subnet and a node operator with nodes in it");

//     let response = submit_proposal(&pic, canister, no_in_subnet.0.clone(), nns, true);
//     assert!(response.is_ok());

//     let response = get_pending(&pic, canister);

//     assert!(response.len() == 1);
//     let proposal = response.first().unwrap();

//     let node_operators_in_subnet = args
//         .subnet_node_operators
//         .iter()
//         .find_map(|arg| {
//             if arg.subnet_id.0 == nns {
//                 Some(arg.node_operators.clone())
//             } else {
//                 None
//             }
//         })
//         .expect("Should find the corresponding number of node operators");

//     let expected_ballots: u8 = node_operators_in_subnet.values().sum();
//     assert_eq!(
//         proposal.node_operator_ballots.len(),
//         expected_ballots as usize,
//         "Received:\n{:?}\nExpected (key * value):\n{:?}",
//         proposal.node_operator_ballots,
//         node_operators_in_subnet
//     );
//     assert!(proposal.proposer.eq(no_in_subnet));

//     let voted_yes: Vec<_> = proposal
//         .node_operator_ballots
//         .iter()
//         .filter(|(_, ballot)| {
//             ballot.eq(&ic_nns_handler_root::root_proposals::RootProposalBallot::Yes)
//         })
//         .collect();

//     let (no_principal, _) = voted_yes.first().unwrap();
//     assert_eq!(no_principal, no_in_subnet);
//     assert_eq!(
//         voted_yes.len(),
//         *node_operators_in_subnet.get(no_in_subnet).unwrap() as usize
//     );

//     let voted_undecided: Vec<_> = proposal
//         .node_operator_ballots
//         .iter()
//         .filter(|(_, ballot)| {
//             ballot.eq(&ic_nns_handler_root::root_proposals::RootProposalBallot::Undecided)
//         })
//         .collect();
//     // All others still didn't vote since its just been proposed
//     assert_eq!(
//         voted_undecided.len() as u8,
//         expected_ballots - voted_yes.len() as u8
//     );
// }
