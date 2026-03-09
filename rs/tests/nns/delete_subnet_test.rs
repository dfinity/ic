/* tag::catalog[]
Title:: Delete Subnet

Goal:: Ensure that subnets can be deleted

end::catalog[] */

use anyhow::Result;
use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_protobuf::registry::subnet::v1::DeletedSubnetListRecord;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::pb::v1::{
    RegistryAtomicMutateRequest, RegistryMutation, registry_mutation,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot,
    install_registry_canister_with_testnet_topology,
};
use ic_system_test_driver::nns::get_subnet_list_from_registry;
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{UniversalCanister, assert_create_agent, block_on};
use ic_types::{Height, RegistryVersion};
use prost::Message;
use registry_canister::init::RegistryCanisterInitPayloadBuilder;
use slog::info;
use std::collections::BTreeSet;
use std::time::Duration;

const NUM_NNS_NODES: usize = 4;
const NUM_APP_NODES: usize = 7;
const DKG_INTERVAL_LENGTH: u64 = 29;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

// Small IC for correctness test pre-master
pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::fast(SubnetType::System, NUM_NNS_NODES)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH)),
        )
        .add_subnet(
            Subnet::fast(SubnetType::Application, NUM_APP_NODES)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH)),
        )
        .add_subnet(
            Subnet::fast(SubnetType::CloudEngine, NUM_APP_NODES)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn test(env: TestEnv) {
    let log = &env.logger();

    // [Phase I] Prepare NNS
    let deleted_subnet_list_mutation = RegistryMutation {
        mutation_type: registry_mutation::Type::Insert as i32,
        key: "deleted_subnet_list".as_bytes().to_vec(),
        value: DeletedSubnetListRecord {
            deleted_subnets: vec![],
        }
        .encode_to_vec(),
    };
    install_registry_canister_with_testnet_topology(
        &env,
        Some(|builder: &mut RegistryCanisterInitPayloadBuilder| {
            builder.push_init_mutate_request(RegistryAtomicMutateRequest {
                mutations: vec![deleted_subnet_list_mutation],
                preconditions: vec![],
            });
        }),
    );
    let topology_snapshot = &env.topology_snapshot();
    let nns_subnet = topology_snapshot.root_subnet();
    let app_subnet = topology_snapshot
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::Application)
        .collect::<Vec<_>>();
    let _app_subnet = app_subnet.first().unwrap();
    let engine_subnet = topology_snapshot
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::CloudEngine)
        .collect::<Vec<_>>();
    let engine_subnet = engine_subnet.first().unwrap();
    let engine_nodes: Vec<IcNodeSnapshot> = engine_subnet.nodes().collect();
    assert_eq!(
        engine_nodes.first().unwrap().subnet_id(),
        Some(engine_subnet.subnet_id)
    );
    let engine_node_ids = BTreeSet::from_iter(engine_nodes.iter().map(|x| x.node_id));
    assert!(
        topology_snapshot
            .unassigned_nodes()
            .collect::<Vec<_>>()
            .is_empty()
    );

    let nns_endpoint = nns_subnet.nodes().next().unwrap();

    let client = RegistryCanister::new_with_query_timeout(
        vec![nns_endpoint.get_public_url()],
        Duration::from_secs(10),
    );

    block_on(async move {
        let nns_agent = assert_create_agent(nns_endpoint.get_public_url().as_str()).await;
        let original_subnets = get_subnet_list_from_registry(&client).await;
        info!(log, "original subnets: {:?}", original_subnets);

        // install a universal canister with the governance canister's canister ID
        let governance_canister =
            UniversalCanister::new(&nns_agent, nns_endpoint.effective_canister_id()).await;

        let arg = DeleteSubnetPayload {
            subnet_id: engine_subnet.subnet_id.get().into(),
        };

        let result_bytes = governance_canister
            .forward_to(
                &REGISTRY_CANISTER_ID.get().0,
                "delete_subnet",
                Encode!(&arg).unwrap(),
            )
            .await
            .unwrap();

        Decode!(&result_bytes, Result<(), String>).unwrap().unwrap();

        let new_topology_snapshot = topology_snapshot
            .block_for_min_registry_version(RegistryVersion::new(2))
            .await
            .expect("Could not obtain updated registry.");
        let unassigned_node_ids = new_topology_snapshot
            .unassigned_nodes()
            .map(|x| x.node_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(unassigned_node_ids, engine_node_ids);

        let final_subnets = get_subnet_list_from_registry(&client).await;
        info!(log, "final subnets: {:?}", final_subnets);
        assert!(!final_subnets.contains(&engine_subnet.subnet_id));
    });
}

#[allow(dead_code)]
#[derive(CandidType)]
struct GetSubnetForCanisterArgs {
    principal: Option<Principal>,
}
#[allow(dead_code)]
#[derive(CandidType, Deserialize)]
struct GetSubnetForCanisterResponse {
    subnet_id: Option<Principal>,
}

#[derive(CandidType)]
pub struct DeleteSubnetPayload {
    subnet_id: Principal,
}
