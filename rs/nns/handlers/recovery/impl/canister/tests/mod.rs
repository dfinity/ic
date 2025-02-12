use std::{collections::BTreeMap, path::PathBuf, time::SystemTime};

use candid::Principal;
use ed25519_dalek::{ed25519::signature::SignerMut, pkcs8::EncodePublicKey, SigningKey};
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_handler_recovery_interface::{
    recovery::{NewRecoveryProposal, RecoveryPayload, RecoveryProposal, VoteOnRecoveryProposal},
    recovery_init::RecoveryInitArgs,
    security_metadata::SecurityMetadata,
    simple_node_operator_record::SimpleNodeOperatorRecord,
    Ballot,
};
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
use rand::rngs::OsRng;
use registry_canister::init::RegistryCanisterInitPayload;
use test_helpers::{
    add_fake_subnet, get_invariant_compliant_subnet_record,
    prepare_registry_with_nodes_and_node_operator_id,
};

mod initial_args_test;
mod node_providers_sync_tests;
mod proposal_logic_tests;
mod test_helpers;
mod voting_tests;

fn fetch_canister_wasm(env: &str) -> Vec<u8> {
    let path: PathBuf = std::env::var(env)
        .unwrap_or_else(|_| panic!("Path should be set in environment variable {env}"))
        .into();
    std::fs::read(&path).unwrap_or_else(|_| panic!("Failed to read path {}", path.display()))
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct NodeOperatorArg {
    principal: PrincipalId,
    num_nodes: u8,
    signing_key: SigningKey,
}

impl From<NodeOperatorArg> for SimpleNodeOperatorRecord {
    fn from(value: NodeOperatorArg) -> Self {
        Self {
            operator_id: value.principal.0,
            nodes: (0..value.num_nodes)
                .map(|i| PrincipalId::new_node_test_id(i as u64).0)
                .collect(),
        }
    }
}

impl NodeOperatorArg {
    fn new(num_nodes: u8) -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        Self {
            principal: PrincipalId::new_self_authenticating(
                &signing_key
                    .verifying_key()
                    .to_public_key_der()
                    .unwrap()
                    .into_vec(),
            ),
            num_nodes,
            signing_key,
        }
    }
}

struct SubnetNodeOperatorArg {
    subnet_id: PrincipalId,
    subnet_type: SubnetType,
    // Operator id : number of nodes in subnet
    node_operators: Vec<NodeOperatorArg>,
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
                        NodeOperatorArg::new(4),
                        NodeOperatorArg::new(4),
                        NodeOperatorArg::new(4),
                        NodeOperatorArg::new(4),
                        NodeOperatorArg::new(4),
                        NodeOperatorArg::new(4),
                        NodeOperatorArg::new(4),
                        NodeOperatorArg::new(4),
                        NodeOperatorArg::new(4),
                        NodeOperatorArg::new(4),
                    ],
                },
                SubnetNodeOperatorArg {
                    subnet_id: PrincipalId::new_subnet_test_id(0),
                    subnet_type: SubnetType::Application,
                    node_operators: vec![NodeOperatorArg::new(4)],
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
        for operator_arg in &arg.node_operators {
            let (mutation, nodes) = prepare_registry_with_nodes_and_node_operator_id(
                operator_mutation_ids,
                operator_arg.num_nodes as u64,
                operator_arg.principal,
            );
            operator_mutation_ids += operator_arg.num_nodes;

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
                SubnetType::System => Some(arg.subnet_id),
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
        fetch_canister_wasm("RECOVERY_WASM_PATH"),
        candid::encode_one(RecoveryInitArgs::default()).unwrap(),
        None,
    );

    // Tick for initial sync
    // 1 - fetch nns
    // 1 - fetch membership
    // 40 - fetch node operators for nodes
    let ticks = arguments
        .subnet_node_operators
        .iter()
        .filter(|subnet| subnet.subnet_type.eq(&SubnetType::System))
        .map(|subnet_arg| {
            subnet_arg
                .node_operators
                .iter()
                .map(|operator_arg| operator_arg.num_nodes)
                .sum::<u8>()
        })
        .sum::<u8>();
    for _ in 0..(ticks + 2) {
        pic.tick();
    }

    (pic, canister)
}

fn submit_proposal(
    pic: &PocketIc,
    canister: Principal,
    sender: &mut NodeOperatorArg,
    arg: RecoveryPayload,
) -> Result<(), String> {
    // Update time so that it doesn't fail the threshold
    pic.set_time(SystemTime::now());

    // Duration from epoch
    let now = SystemTime::UNIX_EPOCH.elapsed().unwrap();
    let seconds_payload = now.as_secs().to_le_bytes().to_vec();
    let signature = sender.signing_key.sign(&seconds_payload);
    let signature = signature.to_vec();

    let response = pic.update_call(
        canister,
        sender.principal.0,
        "submit_new_recovery_proposal",
        candid::encode_one(NewRecoveryProposal {
            payload: arg,
            security_metadata: SecurityMetadata {
                signature,
                payload: seconds_payload,
                pub_key_der: sender
                    .signing_key
                    .verifying_key()
                    .to_public_key_der()
                    .unwrap()
                    .into_vec(),
            },
        })
        .unwrap(),
    );
    let response: Result<(), String> = candid::decode_one(response.unwrap().as_slice()).unwrap();
    println!("{:?}", response);
    response
}

fn get_pending(pic: &PocketIc, canister: Principal) -> Vec<RecoveryProposal> {
    let response = pic
        .query_call(
            canister,
            Principal::anonymous(),
            "get_pending_recovery_proposals",
            candid::encode_one(()).unwrap(),
        )
        .expect("Should be able to fetch remaining proposals");

    let response = candid::decode_one(&response).expect("Should be able to decode response");
    println!("{:?}", response);

    response
}

fn vote_with_only_ballot(
    pic: &PocketIc,
    canister: Principal,
    sender: &mut NodeOperatorArg,
    ballot: Ballot,
) -> Result<(), String> {
    // Add logic for signing so that this is valid
    let pending = get_pending(pic, canister);
    let last = pending.last().unwrap();
    let payload = last.signature_payload().unwrap();
    let signature = sender.signing_key.sign(&payload);
    let signature = signature.to_vec();

    vote(
        pic,
        canister,
        sender.principal.0,
        VoteOnRecoveryProposal {
            security_metadata: SecurityMetadata {
                payload,
                signature,
                pub_key_der: sender
                    .signing_key
                    .verifying_key()
                    .to_public_key_der()
                    .unwrap()
                    .into_vec(),
            },
            ballot,
        },
    )
}

fn vote(
    pic: &PocketIc,
    canister: Principal,
    sender: Principal,
    arg: VoteOnRecoveryProposal,
) -> Result<(), String> {
    let response = pic
        .update_call(
            canister,
            sender,
            "vote_on_proposal",
            candid::encode_one(arg).unwrap(),
        )
        .expect("Should be able to call vote function");

    let response: Result<(), String> =
        candid::decode_one(&response).expect("Should be able to decode response");
    println!("{:?}", response);
    response
}

fn get_current_node_operators(
    pic: &PocketIc,
    canister: Principal,
) -> Vec<SimpleNodeOperatorRecord> {
    let response = pic
        .query_call(
            canister,
            Principal::anonymous(),
            "get_current_nns_node_operators",
            candid::encode_one(()).unwrap(),
        )
        .expect("Should be able to fetch nns node operators");

    let response = candid::decode_one(&response).expect("Should be able to decode response");
    println!("{:?}", response);
    response
}

fn extract_node_operators_from_init_data(
    arguments: &RegistryPreparationArguments,
) -> Vec<NodeOperatorArg> {
    arguments
        .subnet_node_operators
        .iter()
        .find_map(|subnet| match subnet.subnet_type.eq(&SubnetType::System) {
            false => None,
            true => Some(subnet.node_operators.clone()),
        })
        .unwrap()
}
