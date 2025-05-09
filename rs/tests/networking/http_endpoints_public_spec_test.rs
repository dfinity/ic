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

use anyhow::Result;
use ic_agent::Agent;
use ic_crypto_tree_hash::{Label, Path};
use ic_http_endpoints_test_agent::*;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, SubnetSnapshot, TopologySnapshot,
        },
    },
    systest,
    util::{block_on, UniversalCanister},
};
use ic_types::CanisterId;
use itertools::Itertools;
use reqwest::Response;
use slog::{info, Logger};
use std::net::SocketAddr;

const CALL_VERSIONS: [Call; 2] = [Call::V2, Call::V3];

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    let logger = env.logger();
    let snapshot = env.topology_snapshot();

    info!(&logger, "Checking readiness of all nodes...");

    snapshot.subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });

    let (sys_uc1_id, sys_uc2_id, app_uc_id) = get_canister_ids(&snapshot);
    let (sys_agent, app_agent) = get_agents(&snapshot);
    block_on(async {
        // Create three universal canister, two on the system subnet, one on the app subnet
        UniversalCanister::new_with_retries(&sys_agent, sys_uc1_id.into(), &logger).await;
        UniversalCanister::new_with_retries(&sys_agent, sys_uc2_id.into(), &logger).await;
        UniversalCanister::new_with_retries(&app_agent, app_uc_id.into(), &logger).await;
    });
}

fn update_calls(env: TestEnv) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (primary, test_ids) = get_canister_test_ids(&snapshot);
    let socket = get_socket_addr(&snapshot);

    block_on(async {
        // Test that well formed calls get accepted
        for version in CALL_VERSIONS.iter() {
            let response = version
                .call(
                    socket,
                    IngressMessage::default().with_canister_id(primary.into(), primary.into()),
                )
                .await;
            let status = inspect_response(response, "Call", &logger).await;
            assert_2xx(&status);
        }

        // Test that malformed calls get rejects
        for (version, effective_canister_id) in
            CALL_VERSIONS.iter().cartesian_product(test_ids.iter())
        {
            let response = version
                .call(
                    socket,
                    IngressMessage::default()
                        .with_canister_id(primary.into(), (*effective_canister_id).into()),
                )
                .await;
            let status = inspect_response(response, "Call", &logger).await;
            assert_4xx(&status);
        }
    });
}

fn query_calls(env: TestEnv) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (primary, test_ids) = get_canister_test_ids(&snapshot);
    let socket = get_socket_addr(&snapshot);

    block_on(async {
        // Test that well formed calls get accepted
        let response = Query::new(primary.into(), primary.into())
            .query(socket)
            .await;
        let status = inspect_response(response, "Query", &logger).await;
        assert_2xx(&status);

        // Test that malformed calls get rejeceted
        for effective_canister_id in test_ids {
            let response = Query::new(primary.into(), effective_canister_id.into())
                .query(socket)
                .await;
            let status = inspect_response(response, "Query", &logger).await;
            assert_4xx(&status);
        }
    });
}

fn read_state(env: TestEnv) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (primary, test_ids) = get_canister_test_ids(&snapshot);
    let socket = get_socket_addr(&snapshot);

    block_on(async {
        // Test that well formed read state requests work
        let response = CanisterReadState::new(
            vec![Path::from(vec![
                Label::from("canister"),
                Label::from(primary),
                Label::from("controllers"),
            ])],
            primary.into(),
        )
        .read_state(socket)
        .await;
        let status = inspect_response(response, "ReadState", &logger).await;
        assert_2xx(&status);

        // Test that malformed read_state requests are rejected
        for effective_canister_id in test_ids {
            let response = CanisterReadState::new(
                vec![Path::from(vec![
                    Label::from("canister"),
                    Label::from(effective_canister_id),
                    Label::from("controllers"),
                ])],
                primary.into(),
            )
            .read_state(socket)
            .await;
            let status = inspect_response(response, "ReadState", &logger).await;
            assert_4xx(&status);
        }
    });
}

fn read_time(env: TestEnv) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (primary, _) = get_canister_test_ids(&snapshot);
    let socket = get_socket_addr(&snapshot);

    block_on(async {
        // Test that calling "time" path on the existing canister id works
        let response =
            CanisterReadState::new(vec![Path::from(Label::from("time"))], primary.into())
                .read_state(socket)
                .await;
        let status = inspect_response(response, "ReadState", &logger).await;
        assert_2xx(&status);

        // Test that calling "time" on the management canister
        // NOTE: On a boundary node this would get rejected, since the boundary node is not able to route
        // the call, since it's not clear which subnet it should route to.
        // Without a boundary node, this call is just fine
        let response = CanisterReadState::new(
            vec![Path::from(Label::from("time"))],
            CanisterId::ic_00().into(),
        )
        .read_state(socket)
        .await;
        let status = inspect_response(response, "ReadState", &logger).await;
        assert_2xx(&status);
    });
}

async fn inspect_response(response: Response, typ: &str, logger: &Logger) -> u16 {
    let status = response.status().as_u16();
    let text = if !(200..300).contains(&status) {
        format!("Reason: {}", response.text().await.unwrap())
    } else {
        String::default()
    };

    info!(logger, "{}: Got response status: {} {}", typ, status, text);

    status
}

fn get_subnets(snapshot: &TopologySnapshot) -> (SubnetSnapshot, SubnetSnapshot) {
    let sys_subnet = snapshot
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::System)
        .expect("Failed to find system subnet");
    let app_subnet = snapshot
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("Failed to find app subnet");

    (sys_subnet, app_subnet)
}

fn get_agents(snapshot: &TopologySnapshot) -> (Agent, Agent) {
    let (sys_subnet, app_subnet) = get_subnets(snapshot);

    let sys_node = sys_subnet.nodes().next().unwrap();
    let sys_agent = sys_node.build_default_agent();
    let app_agent = app_subnet.nodes().next().unwrap().build_default_agent();

    (sys_agent, app_agent)
}

fn get_canister_ids(snapshot: &TopologySnapshot) -> (CanisterId, CanisterId, CanisterId) {
    let (sys_subnet, app_subnet) = get_subnets(snapshot);

    let sys_subnet_canister_id_range = sys_subnet.subnet_canister_ranges()[0];
    let sys_uc1_id = sys_subnet_canister_id_range
        .generate_canister_id(None)
        .unwrap();
    let sys_uc2_id = sys_subnet_canister_id_range
        .generate_canister_id(Some(sys_uc1_id))
        .unwrap();

    let app_subnet_canister_id_range = app_subnet.subnet_canister_ranges()[0];
    let app_uc_id = app_subnet_canister_id_range
        .generate_canister_id(None)
        .unwrap();

    (sys_uc1_id, sys_uc2_id, app_uc_id)
}

fn get_socket_addr(snapshot: &TopologySnapshot) -> SocketAddr {
    let (sys_subnet, _) = get_subnets(snapshot);
    let sys_node = sys_subnet.nodes().next().unwrap();
    SocketAddr::new(sys_node.get_ip_addr(), 8080)
}

fn get_canister_test_ids(snapshot: &TopologySnapshot) -> (CanisterId, [CanisterId; 4]) {
    let (primary, sys_uc, app_uc) = get_canister_ids(snapshot);
    (
        primary,
        [
            // Valid destination on same subnet
            sys_uc,
            // Valid destination on other subnet
            app_uc,
            // Invalid canister id
            CanisterId::from(1337),
            // Management canister
            CanisterId::ic_00(),
        ],
    )
}

fn assert_2xx(status: &u16) {
    assert!((200..300).contains(status));
}

fn assert_4xx(status: &u16) {
    assert!((400..500).contains(status))
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(update_calls))
        .add_test(systest!(query_calls))
        .add_test(systest!(read_state))
        .add_test(systest!(read_time))
        .execute_from_args()?;

    Ok(())
}
