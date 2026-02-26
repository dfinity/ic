/* tag::catalog[]
Title:: Delete Subnet

Goal:: Ensure that subnets can be deleted

end::catalog[] */

use anyhow::Result;
use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, NnsInstallationBuilder,
    SubnetSnapshot, install_registry_canister_with_testnet_topology,
};
use ic_system_test_driver::nns::get_subnet_list_from_registry;
use ic_system_test_driver::nns::{self, get_software_version_from_snapshot};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{block_on, runtime_from_url};
use ic_types::{Height, RegistryVersion};
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
    install_registry_canister_with_testnet_topology(&env, None);
    let topology_snapshot = &env.topology_snapshot();
    let nns_subnet = topology_snapshot.root_subnet();
    let app_subnets: Vec<SubnetSnapshot> = topology_snapshot
        .subnets()
        .filter(|s| s.subnet_type() == SubnetType::Application)
        .collect();
    let app_subnet_1 = app_subnets[0].clone();
    let app_subnet_2 = app_subnets[1].clone();
    let app_subnet_2_nodes: Vec<IcNodeSnapshot> = app_subnet_2.nodes().collect();
    assert_eq!(
        app_subnet_2_nodes.first().unwrap().subnet_id(),
        Some(app_subnet_2.subnet_id)
    );
    let app_subnet_2_node_ids = BTreeSet::from_iter(app_subnet_2_nodes.iter().map(|x| x.node_id));
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
        let original_subnets = get_subnet_list_from_registry(&client).await;
        info!(log, "original subnets: {:?}", original_subnets);

        // get current replica version and Governance canister
        let version = get_software_version_from_snapshot(&nns_endpoint)
            .await
            .expect("could not obtain replica software version");
        let nns = runtime_from_url(
            nns_endpoint.get_public_url(),
            nns_endpoint.effective_canister_id(),
        );
        let registry_canister = nns::get_registry_canister(&nns);

        let bytes = registry_canister
            .query("get_subnet_for_canister")
            .bytes(
                Encode!(&GetSubnetForCanisterArgs {
                    principal: Some(REGISTRY_CANISTER_ID.into())
                })
                .unwrap(),
            )
            .await
            .unwrap();
        let Ok(GetSubnetForCanisterResponse { subnet_id }) =
            Decode!(&bytes, Result<GetSubnetForCanisterResponse, String>).unwrap()
        else {
            panic!("Expected Ok(_)");
        };

        let arg = DeleteSubnetPayload {
            subnet_id: app_subnet_2.subnet_id.get().into(),
        };
        let bytes = registry_canister
            .update("delete_subnet")
            .bytes(Encode!(&arg).unwrap())
            .await
            .unwrap();
        let Ok(()) = Decode!(&bytes, Result<(), String>).unwrap() else {
            panic!("Expected Ok(())")
        };

        let new_topology_snapshot = topology_snapshot
            .block_for_min_registry_version(RegistryVersion::new(2))
            .await
            .expect("Could not obtain updated registry.");
        let unassigned_node_ids = new_topology_snapshot
            .unassigned_nodes()
            .map(|x| x.node_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(unassigned_node_ids, app_subnet_2_node_ids);

        let final_subnets = get_subnet_list_from_registry(&client).await;
        info!(log, "final subnets: {:?}", final_subnets);
        assert!(!final_subnets.contains(&app_subnet_2.subnet_id));
    });
}

#[derive(CandidType)]
struct GetSubnetForCanisterArgs {
    principal: Option<Principal>,
}
#[derive(CandidType, Deserialize)]
struct GetSubnetForCanisterResponse {
    subnet_id: Option<Principal>,
}

#[derive(CandidType)]
pub struct DeleteSubnetPayload {
    subnet_id: Principal,
}
