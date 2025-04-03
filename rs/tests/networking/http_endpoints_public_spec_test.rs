/* tag::catalog[]
Title:: Basic HTTP requests from canisters

Goal:: Ensure simple HTTP requests can be made from canisters.

Runbook::
0. Create an IC with two subnets with one node each
1. Instanciate two universal canisters, two on the system subnet, one on the app subnet
2. Run the specific spec tests


Success::
1. Received expected http response code as per specification


Effective Canister test:
1. Update call with canister_id A to the endpoint /api/v{2,3}/canister/B/call with a different canister ID B in the URL is rejected with 4xx;
2. Query call with canister_id A to the endpoint /api/v2/canister/B/query with a different canister ID B in the URL is rejected with 4xx;
3. Read state request for the path /canisters/A/controllers to the endpoint /api/v2/canister/B/read_state with a different canister ID B in the URL is rejected with 4xx;
4. Read state request for the path /time to the endpoint /api/v2/canister/aaaaa-aa/read_state is rejected with 4xx.

The different canister ID B is
1. The canister ID of a different canister on the same subnet;
2. The canister ID of a different canister on a different subnet;
3. A malformed principal;
4. The management canister ID.


end::catalog[] */

use anyhow::{bail, Result};
use ic_http_endpoints_test_agent::*;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer},
    },
    systest,
    util::{block_on, UniversalCanister},
};
use ic_types::CanisterId;
use itertools::Itertools;
use slog::info;

const CALL_VERSIONS: [Call; 2] = [Call::V2, Call::V3];

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    info!(&env.logger(), "Checking readiness of all nodes...");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

fn test(env: TestEnv) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();

    // Get the system subnet, setup an agent and get two canister ids from the range
    let sys_subnet = snapshot
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::System)
        .expect("Failed to find system subnet");
    let sys_node = sys_subnet
        .nodes()
        .next()
        .expect("Failed to find node in system subnet");
    let sys_subnet_canister_id_range = sys_subnet.subnet_canister_ranges()[0];
    let sys_uc1_id = sys_subnet_canister_id_range
        .generate_canister_id(None)
        .unwrap();
    let sys_uc2_id = sys_subnet_canister_id_range
        .generate_canister_id(Some(sys_uc1_id))
        .unwrap();

    let sys_node = sys_subnet.nodes().next().unwrap();
    let sys_agent = sys_node.build_default_agent();
    let sys_socket_addr = std::net::SocketAddr::new(sys_node.get_ip_addr(), 8080);

    // Get the app subnet, setup an agent and get a cansiter id from the range
    let app_subnet = snapshot
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("Failed to find app subnet");
    let app_node = app_subnet
        .nodes()
        .next()
        .expect("Failed to find node in system subnet");
    let app_uc_id = app_node.effective_canister_id();
    let app_agent = app_subnet.nodes().next().unwrap().build_default_agent();

    block_on(async {
        // Create three universal canister, two on the system sybnet, one on the app subnet
        let sys_uc1 =
            UniversalCanister::new_with_retries(&sys_agent, sys_uc1_id.into(), &logger).await;
        let sys_uc2 =
            UniversalCanister::new_with_retries(&sys_agent, sys_uc2_id.into(), &logger).await;
        let app_uc = UniversalCanister::new_with_retries(&app_agent, app_uc_id, &logger).await;

        let test_canister_ids: [CanisterId; 4] = [
            // Valid destination on same subnet
            sys_uc2_id,
            // Valid destination on other subnet
            CanisterId::try_from_principal_id(app_uc_id).unwrap(),
            // Invalid canister id
            CanisterId::from(1337),
            // Management canister
            CanisterId::ic_00(),
        ];

        // Test making update calls
        for (version, canister_id) in CALL_VERSIONS
            .iter()
            .cartesian_product(test_canister_ids.iter())
        {
            let response = version
                .call(
                    sys_socket_addr,
                    IngressMessage::default()
                        .with_canister_id(sys_uc1_id.into(), (*canister_id).into()),
                )
                .await;
            info!(logger, "Got response status: {}", response.status());
            // TODO
        }

        // TODO
    });
    todo!()
}
