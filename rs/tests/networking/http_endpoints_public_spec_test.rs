/* tag::catalog[]
Title:: IC public HTTP interface tests.

Goal:: IC public HTTP interface complies with public Interface Specification.

Runbook::
0. Create an IC with one API BN and two subnets (one system subnet and one app subnet) each with one node.
1. Instantiate two universal canisters on the system subnet and one universal canister on the app subnet.
2. Run the specific specification compliance tests.


Success::
1. Received expected HTTP response code as per specification.


Invalid effective canister ID tests:
1. Update call with canister_id A to the endpoint /api/v{2,3,4}/canister/B/call with a different canister ID B in the URL is rejected with 4xx;
2. Query call with canister_id A to the endpoint /api/v{2,3}/canister/B/query with a different canister ID B in the URL is rejected with 4xx;
3. Read state request for the path /canisters/A/controllers to the endpoints /api/{v2,v3}/canister/B/read_state with a different canister ID B in the URL is rejected with 4xx;
4. Read state request for the path /time to the endpoints /api/{v2,v3}/canister/aaaaa-aa/read_state is rejected with 4xx.

The different canister ID B is
1. The canister ID of a different canister on the same subnet;
2. The canister ID of a different canister on a different subnet;
3. A malformed principal (invalid textual representation);
4. The management canister ID.


Invalid HTTP request body tests:
1. Update call with omitted sender (anonymous principal) is rejected with 4xx.
2. Update call with omitted request type is rejected with 4xx.
3. Update call with wrong request type is rejected with 4xx.

end::catalog[] */

use anyhow::Result;
use candid::Principal;
use ic_agent::Agent;
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_crypto_tree_hash::{Label, Path};
use ic_http_endpoints_public::{query, read_state};
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
    util::{UniversalCanister, block_on},
};
use ic_types::messages::{Blob, HttpRequestEnvelope};
use ic_types::{CanisterId, PrincipalId};
use ic_universal_canister::wasm;
use reqwest::{Response, StatusCode};
use serde::Serialize;
use slog::{Logger, info};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    let logger = env.logger();
    let snapshot = env.topology_snapshot();

    install_nns_and_check_progress(env.topology_snapshot());

    info!(&logger, "Checking readiness of all API boundary nodes...");

    for api_bn in env.topology_snapshot().api_boundary_nodes() {
        api_bn
            .await_status_is_healthy()
            .expect("API boundary node did not come up healthy.");
    }

    let (sys_uc1_id, sys_uc2_id, app_uc_id) = get_canister_ids(&snapshot);
    let (sys_agent, app_agent) = get_agents(&snapshot);
    block_on(async {
        // Create three universal canister, two on the system subnet, one on the app subnet
        UniversalCanister::new_with_retries(&sys_agent, sys_uc1_id.into(), &logger).await;
        UniversalCanister::new_with_retries(&sys_agent, sys_uc2_id.into(), &logger).await;
        UniversalCanister::new_with_retries(&app_agent, app_uc_id.into(), &logger).await;
    });
}

fn update_calls(env: TestEnv, version: Call) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (primary, test_ids) = get_canister_test_ids(&snapshot);
    let socket = get_socket_addr(&snapshot);

    block_on(async {
        // Test that well formed calls get accepted
        let response = version
            .call(
                socket,
                IngressMessage::default().with_canister_id(primary.into(), primary.into()),
            )
            .await;
        let status = inspect_response(response, "Call", &logger).await;
        assert_2xx(&status);

        // Test that malformed calls get rejects
        for effective_canister_id in test_ids {
            let response = version
                .call(
                    socket,
                    IngressMessage::default()
                        .with_canister_id(primary.into(), effective_canister_id.into()),
                )
                .await;
            let status = inspect_response(response, "Call", &logger).await;
            assert_4xx(&status);
        }
    });
}

fn query_calls(env: TestEnv, version: query::Version) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (primary, test_ids) = get_canister_test_ids(&snapshot);
    let socket = get_socket_addr(&snapshot);

    block_on(async {
        // Test that well formed calls get accepted
        let response = Query::new(primary.into(), primary.into(), version)
            .query(socket)
            .await;
        let status = inspect_response(response, "Query", &logger).await;
        assert_2xx(&status);

        // Test that malformed calls get rejeceted
        for effective_canister_id in test_ids {
            let response = Query::new(primary.into(), effective_canister_id.into(), version)
                .query(socket)
                .await;
            let status = inspect_response(response, "Query", &logger).await;
            assert_4xx(&status);
        }
    });
}

fn read_state_valid_succeeds(env: TestEnv, version: read_state::canister::Version) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (primary, _test_ids) = get_canister_test_ids(&snapshot);
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
            version,
        )
        .read_state(socket)
        .await;
        let status = inspect_response(response, "ReadState", &logger).await;
        assert_2xx(&status);
    });
}

fn read_state_malformed_rejected(env: TestEnv, version: read_state::canister::Version) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (primary, test_ids) = get_canister_test_ids(&snapshot);
    let socket = get_socket_addr(&snapshot);

    block_on(async {
        // Test that malformed read_state requests are rejected
        for effective_canister_id in test_ids {
            let response = CanisterReadState::new(
                vec![Path::from(vec![
                    Label::from("canister"),
                    Label::from(primary),
                    Label::from("controllers"),
                ])],
                effective_canister_id.into(),
                version,
            )
            .read_state(socket)
            .await;
            let status = inspect_response(response, "ReadState", &logger).await;
            assert_4xx(&status);
        }
    });
}

fn read_time(env: TestEnv, version: read_state::canister::Version) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (primary, _) = get_canister_test_ids(&snapshot);
    let subnet_replica_url = get_subnet_replica_url(&snapshot);
    let api_bn_url = get_api_bn_url(&snapshot);

    block_on(async {
        // Test that requesting the "time" path on an existing canister id works.
        let read_state = |effective_canister_id: CanisterId, url: Url| {
            CanisterReadState::new(
                vec![Path::from(Label::from("time"))],
                effective_canister_id.into(),
                version,
            )
            .read_state_at_url(url)
        };

        let response = read_state(primary, subnet_replica_url.clone()).await;
        let status = inspect_response(response, "ReadState", &logger).await;
        assert_2xx(&status);

        let response = read_state(primary, api_bn_url.clone()).await;
        let status = inspect_response(response, "ReadState", &logger).await;
        match version {
            read_state::canister::Version::V2 => {
                assert_2xx(&status);
            }
            read_state::canister::Version::V3 => {
                // TODO(CON-1586): change it to 2xx once the boundary node supports the new endpoint
                assert_4xx(&status);
            }
        }

        // Test that requesting the "time" path on the management canister id fails when using API boundary nodes.
        let response = read_state(CanisterId::ic_00(), api_bn_url).await;
        let status = inspect_response(response, "ReadState", &logger).await;
        assert_4xx(&status);

        // Test that requesting the "time" path on the management canister id works when bypassing API boundary nodes.
        let response = read_state(CanisterId::ic_00(), subnet_replica_url).await;
        let status = inspect_response(response, "ReadState", &logger).await;
        assert_2xx(&status);
    });
}

fn invalid_http_request_body(env: TestEnv) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (primary, _test_ids) = get_canister_test_ids(&snapshot);
    let subnet_replica_url = get_subnet_replica_url(&snapshot);
    let api_bn_url = get_api_bn_url(&snapshot);

    block_on(async {
        for url in [subnet_replica_url, api_bn_url] {
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap();

            let mut update_url = url;
            update_url.set_path(&format!("/api/v2/canister/{}/call", primary));

            info!(logger, "Well-formed update call to {}", update_url);
            #[derive(Serialize)]
            pub struct HttpCanisterUpdate {
                pub request_type: String,
                pub canister_id: Blob,
                pub method_name: String,
                pub arg: Blob,
                pub sender: Blob,
                pub ingress_expiry: u64,
            }
            let ingress_expiry =
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(3 * 60);
            let envelope: HttpRequestEnvelope<HttpCanisterUpdate> = HttpRequestEnvelope {
                content: HttpCanisterUpdate {
                    request_type: "call".to_string(),
                    canister_id: Blob(primary.get().as_slice().to_vec()),
                    method_name: "update".to_string(),
                    arg: Blob(wasm().reply().build()),
                    sender: Blob(Principal::anonymous().as_slice().to_vec()),
                    ingress_expiry: ingress_expiry.as_nanos() as u64,
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };
            let bytes = serde_cbor::to_vec(&envelope).unwrap();
            let resp = client
                .post(update_url.clone())
                .header("Content-Type", "application/cbor")
                .body(bytes)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::ACCEPTED);

            info!(
                logger,
                "Malformed update call (missing `sender`) to {}", update_url
            );
            #[derive(Serialize)]
            pub struct NoSenderHttpCanisterUpdate {
                pub request_type: String,
                pub canister_id: Blob,
                pub method_name: String,
                pub arg: Blob,
                pub ingress_expiry: u64,
            }
            let ingress_expiry =
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(3 * 60);
            let envelope: HttpRequestEnvelope<NoSenderHttpCanisterUpdate> = HttpRequestEnvelope {
                content: NoSenderHttpCanisterUpdate {
                    request_type: "call".to_string(),
                    canister_id: Blob(primary.get().as_slice().to_vec()),
                    method_name: "update".to_string(),
                    arg: Blob(wasm().reply().build()),
                    ingress_expiry: ingress_expiry.as_nanos() as u64,
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };
            let bytes = serde_cbor::to_vec(&envelope).unwrap();
            let resp = client
                .post(update_url.clone())
                .header("Content-Type", "application/cbor")
                .body(bytes)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let bytes = resp.bytes().await.unwrap();
            let err = String::from_utf8(bytes.to_vec()).unwrap();
            info!(logger, "Response: {}", err);
            assert!(err.contains("missing field `sender`"));

            info!(
                logger,
                "Malformed update call (missing `request_type`) to {}", update_url
            );
            #[derive(Serialize)]
            pub struct NoRequestTypeHttpCanisterUpdate {
                pub canister_id: Blob,
                pub method_name: String,
                pub arg: Blob,
                pub sender: Blob,
                pub ingress_expiry: u64,
            }
            let ingress_expiry =
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(3 * 60);
            let envelope: HttpRequestEnvelope<NoRequestTypeHttpCanisterUpdate> =
                HttpRequestEnvelope {
                    content: NoRequestTypeHttpCanisterUpdate {
                        canister_id: Blob(primary.get().as_slice().to_vec()),
                        method_name: "update".to_string(),
                        arg: Blob(wasm().reply().build()),
                        sender: Blob(Principal::anonymous().as_slice().to_vec()),
                        ingress_expiry: ingress_expiry.as_nanos() as u64,
                    },
                    sender_pubkey: None,
                    sender_sig: None,
                    sender_delegation: None,
                };
            let bytes = serde_cbor::to_vec(&envelope).unwrap();
            let resp = client
                .post(update_url.clone())
                .header("Content-Type", "application/cbor")
                .body(bytes)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let bytes = resp.bytes().await.unwrap();
            let err = String::from_utf8(bytes.to_vec()).unwrap();
            info!(logger, "Response: {}", err);
            assert!(err.contains("missing field `request_type`"));

            info!(
                logger,
                "Malformed update call (wrong `request_type`) to {}", update_url
            );
            let ingress_expiry =
                SystemTime::now().duration_since(UNIX_EPOCH).unwrap() + Duration::from_secs(3 * 60);
            let envelope: HttpRequestEnvelope<HttpCanisterUpdate> = HttpRequestEnvelope {
                content: HttpCanisterUpdate {
                    request_type: "query".to_string(),
                    canister_id: Blob(primary.get().as_slice().to_vec()),
                    method_name: "update".to_string(),
                    arg: Blob(wasm().reply().build()),
                    sender: Blob(Principal::anonymous().as_slice().to_vec()),
                    ingress_expiry: ingress_expiry.as_nanos() as u64,
                },
                sender_pubkey: None,
                sender_sig: None,
                sender_delegation: None,
            };
            let bytes = serde_cbor::to_vec(&envelope).unwrap();
            let resp = client
                .post(update_url)
                .header("Content-Type", "application/cbor")
                .body(bytes)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            let bytes = resp.bytes().await.unwrap();
            let err = String::from_utf8(bytes.to_vec()).unwrap();
            info!(logger, "Response: {}", err);
            assert!(err.contains("unknown variant `query`, expected `call`"));
        }
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

fn get_subnet_replica_url(snapshot: &TopologySnapshot) -> Url {
    let (sys_subnet, _) = get_subnets(snapshot);
    let sys_node = sys_subnet.nodes().next().unwrap();
    sys_node.get_public_url()
}

fn get_api_bn_url(snapshot: &TopologySnapshot) -> Url {
    let api_bn = snapshot
        .api_boundary_nodes()
        .next()
        .expect("There should be at least one API boundary node");
    api_bn.get_public_url()
}

fn get_canister_test_ids(snapshot: &TopologySnapshot) -> (CanisterId, [CanisterId; 5]) {
    let (primary, sys_uc, app_uc) = get_canister_ids(snapshot);
    (
        primary,
        [
            // Valid destination on same subnet
            sys_uc,
            // Valid destination on other subnet
            app_uc,
            // Non-existing canister id
            CanisterId::from(1337),
            // Management canister
            CanisterId::ic_00(),
            // Invalid canister id
            CanisterId::try_from(PrincipalId::new_user_test_id(42)).unwrap(),
        ],
    )
}

fn assert_2xx(status: &u16) {
    assert!(
        (200..300).contains(status),
        "Received non-success status: {status}"
    );
}

fn assert_4xx(status: &u16) {
    assert!(
        (400..500).contains(status),
        "Received non-user-error status: {status}"
    );
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(query_calls; query::Version::V2))
        .add_test(systest!(query_calls; query::Version::V3))
        .add_test(systest!(update_calls; Call::V2))
        .add_test(systest!(update_calls; Call::V3))
        .add_test(systest!(update_calls; Call::V4))
        .add_test(systest!(read_state_valid_succeeds; read_state::canister::Version::V2))
        .add_test(systest!(read_state_valid_succeeds; read_state::canister::Version::V3))
        .add_test(systest!(read_state_malformed_rejected; read_state::canister::Version::V2))
        .add_test(systest!(read_state_malformed_rejected; read_state::canister::Version::V3))
        .add_test(systest!(read_time; read_state::canister::Version::V2))
        .add_test(systest!(read_time; read_state::canister::Version::V3))
        .add_test(systest!(invalid_http_request_body))
        .execute_from_args()?;

    Ok(())
}
