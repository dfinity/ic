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
3. Invalid canister ID (non-existing canister, user ID).
4. The management canister ID.


Malformed HTTP request tests:
1. Update call with omitted sender (anonymous principal) is rejected with 4xx.
2. Update call with omitted request type is rejected with 4xx.
3. Update call with wrong request type is rejected with 4xx.
4. Update call with malformed textual representation of its effective canister ID is rejected with 4xx.


Edge cases for method names in update and query calls:
- empty method name (succeeds if the canister exports a method with an empty name, fails gracefully otherwise);
- method name with spaces (succeeds if the canister exports a method whose name contains spaces, fails gracefully otherwise);
- long method name (succeeds if the canister exports a method with a long name, fails gracefully otherwise);
- too long method name (always fails gracefully).

end::catalog[] */

use anyhow::Result;
use candid::Principal;
use ic_agent::{Agent, AgentError};
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
use ic_types::{CanisterId, PrincipalId};
use ic_universal_canister::wasm;
use ic_utils::interfaces::ManagementCanister;
use ic_utils::interfaces::management_canister::builders::InstallMode;
use maplit::btreemap;
use reqwest::{Response, StatusCode};
use serde_cbor::Value;
use slog::{Logger, info};
use std::collections::BTreeMap;
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
    let subnet_replica_url = get_sys_subnet_replica_url(&snapshot);
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
                assert_2xx(&status);
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

fn malformed_http_request(env: TestEnv) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (primary, _test_ids) = get_canister_test_ids(&snapshot);
    let subnet_replica_url = get_sys_subnet_replica_url(&snapshot);
    let api_bn_url = get_api_bn_url(&snapshot);

    block_on(async {
        for url in [subnet_replica_url, api_bn_url] {
            let call_content = btreemap! {
                    Value::Text("canister_id".to_string()) => Value::Bytes(primary.get().as_slice().to_vec()),
                    Value::Text("method_name".to_string()) => Value::Text("query".to_string()),
                    Value::Text("arg".to_string()) => Value::Bytes(wasm().reply().build()),
            };
            let read_state_content = btreemap! {
                    Value::Text("paths".to_string()) => Value::Array(vec![]),
            };
            for (request_type, version, content, wrong_request_type) in [
                ("call", "v2", call_content.clone(), "query"),
                ("call", "v3", call_content.clone(), "query"),
                ("call", "v4", call_content.clone(), "query"),
                ("query", "v2", call_content.clone(), "call"),
                ("query", "v3", call_content.clone(), "call"),
                ("read_state", "v2", read_state_content.clone(), "query"),
                ("read state", "v3", read_state_content.clone(), "query"),
            ] {
                let mut request_url = url.clone();
                request_url.set_path(&format!(
                    "/api/{}/canister/{}/{}",
                    version, primary, request_type
                ));
                let mut malformed_url = url.clone();
                malformed_url.set_path(&format!(
                    "/api/{}/canister/this-is-not-a-valid-canister-id/{}",
                    version, request_type
                ));

                let mut valid_content = btreemap! {
                    Value::Text("request_type".to_string()) => Value::Text(request_type.to_string()),
                    Value::Text("sender".to_string()) => Value::Bytes(Principal::anonymous().as_slice().to_vec()),
                };
                valid_content.extend(content.into_iter());
                let envelope = |mut content: BTreeMap<Value, Value>| {
                    let ingress_expiry = SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
                        + Duration::from_secs(3 * 60);
                    content.insert(
                        Value::Text("ingress_expiry".to_string()),
                        Value::Integer(ingress_expiry.as_nanos() as i128),
                    );
                    Value::Map(
                        btreemap! {Value::Text("content".to_string()) => Value::Map(content) },
                    )
                };
                let bytes = serde_cbor::to_vec(&envelope(valid_content.clone())).unwrap();
                let client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .build()
                    .unwrap();
                let resp = client
                    .post(request_url.clone())
                    .header("Content-Type", "application/cbor")
                    .body(bytes)
                    .send()
                    .await
                    .unwrap();
                assert!(
                    resp.status().is_success(),
                    "Expected success but got {} for {request_type} {version}",
                    resp.status()
                );

                let assert_bad_request =
                    |logger: Logger,
                     url: Url,
                     content: BTreeMap<Value, Value>,
                     expected_err: String| async move {
                        let client = reqwest::Client::builder()
                            .danger_accept_invalid_certs(true)
                            .build()
                            .unwrap();
                        let bytes = serde_cbor::to_vec(&envelope(content)).unwrap();
                        let resp = client
                            .post(url)
                            .header("Content-Type", "application/cbor")
                            .body(bytes)
                            .send()
                            .await
                            .unwrap();
                        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
                        let bytes = resp.bytes().await.unwrap();
                        let err = String::from_utf8(bytes.to_vec()).unwrap();
                        info!(logger, "Response: {}", err);
                        assert!(err.contains(&expected_err));
                    };

                let mut no_sender_content = valid_content.clone();
                no_sender_content
                    .remove(&Value::Text("sender".to_string()))
                    .unwrap();
                assert_bad_request(
                    logger.clone(),
                    request_url.clone(),
                    no_sender_content,
                    "missing field `sender`".to_string(),
                )
                .await;

                let mut no_request_type_content = valid_content.clone();
                no_request_type_content
                    .remove(&Value::Text("request_type".to_string()))
                    .unwrap();
                assert_bad_request(
                    logger.clone(),
                    request_url.clone(),
                    no_request_type_content,
                    "missing field `request_type`".to_string(),
                )
                .await;

                let mut wrong_request_type_content = valid_content.clone();
                wrong_request_type_content
                    .insert(
                        Value::Text("request_type".to_string()),
                        Value::Text(wrong_request_type.to_string()),
                    )
                    .unwrap();
                assert_bad_request(
                    logger.clone(),
                    request_url.clone(),
                    wrong_request_type_content,
                    format!(
                        "unknown variant `{}`, expected `{}`",
                        wrong_request_type, request_type
                    ),
                )
                .await;

                assert_bad_request(
                    logger.clone(),
                    malformed_url.clone(),
                    valid_content,
                    "Text must be in valid Base32 encoding.".to_string(),
                )
                .await;
            }
        }
    });
}

fn wasm_with_exported_method_name(method_name: String) -> Vec<u8> {
    let wat = format!(
        r#"
(module
    (import "ic0" "msg_reply" (func $msg_reply))
    (func $foo
        (call $msg_reply)
    )
    (memory 1)
    (export "canister_query {}" (func $foo))
)"#,
        method_name
    );
    wat::parse_str(wat).unwrap()
}

async fn deploy_wasm_to_fresh_canister(
    agent: &Agent,
    effective_canister_id: Principal,
    wasm: &[u8],
) -> Principal {
    let ic00 = ManagementCanister::create(agent);
    let canister_id = ic00
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait()
        .await
        .unwrap()
        .0;
    ic00.install_code(&canister_id, wasm)
        .with_mode(InstallMode::Reinstall)
        .call_and_wait()
        .await
        .unwrap();
    canister_id
}

fn method_name_edge_cases(env: TestEnv) {
    let snapshot = env.topology_snapshot();

    // We use an application subnet in this test
    // since its update call size limits are lower
    // and thus we can easily test the case of
    // an update call already failing with HTTP status code 413
    // and a query call still returning a reject.
    let (_primary, _sys_uc, app_uc) = get_canister_ids(&snapshot);
    let subnet_replica_url = get_app_subnet_replica_url(&snapshot);
    let api_bn_url = get_api_bn_url(&snapshot);

    block_on(async {
        for (url, is_api_bn) in [(subnet_replica_url, false), (api_bn_url, true)] {
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap();
            let agent = Agent::builder()
                .with_url(url.clone())
                .with_http_client(client)
                .build()
                .unwrap();
            agent.fetch_root_key().await.unwrap();

            for method_name in [
                "",
                "method name with spaces",
                &'x'.to_string().repeat(10_000),
                &'x'.to_string().repeat(20_000),
            ] {
                // We start with the successful case of a canister
                // actually exporting a method with the given name.
                let wasm = wasm_with_exported_method_name(method_name.to_string());
                let canister_id =
                    deploy_wasm_to_fresh_canister(&agent, app_uc.into(), wasm.as_slice()).await;

                let response = agent
                    .update(&canister_id, method_name)
                    .call_and_wait()
                    .await
                    .unwrap();
                assert!(response.is_empty());
                let response = agent.query(&canister_id, method_name).call().await.unwrap();
                assert!(response.is_empty());

                // We continue with testing graceful handling of method names
                // not exported by the canister.
                // To this end, we use a trivial WASM exporting no method.
                let trivial_wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
                // We deploy a fresh canister to prevent test flakiness due to query caching.
                let canister_id =
                    deploy_wasm_to_fresh_canister(&agent, app_uc.into(), trivial_wasm.as_slice())
                        .await;

                let short_method_name = &method_name[..std::cmp::min(method_name.len(), 50)];
                let err: AgentError = agent
                    .update(&canister_id, method_name)
                    .call_and_wait()
                    .await
                    .unwrap_err();
                assert!(
                    matches!(err, AgentError::CertifiedReject { .. }),
                    "update: {} ({}) got error: {}",
                    short_method_name,
                    method_name.len(),
                    err
                );
                let err = agent
                    .query(&canister_id, method_name)
                    .call()
                    .await
                    .unwrap_err();
                assert!(
                    matches!(err, AgentError::UncertifiedReject { .. }),
                    "query: {} ({}) got error: {}",
                    short_method_name,
                    method_name.len(),
                    err
                );
            }

            // For the failure cases, we just need a canister.
            // The actual method name does not matter.
            let trivial_wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
            let canister_id =
                deploy_wasm_to_fresh_canister(&agent, app_uc.into(), trivial_wasm.as_slice()).await;
            let too_long_method_name = 'x'.to_string().repeat(1 << 20);
            let err = agent
                .update(&canister_id, &too_long_method_name)
                .call_and_wait()
                .await
                .unwrap_err();

            if is_api_bn {
                // When going through the API BN, the request is rejected with HTTP 400 Bad Request.
                assert!(
                    matches!(err, AgentError::HttpError(ref payload) if payload.status == StatusCode::BAD_REQUEST.as_u16()),
                    "api bn update for 'x' * 2**20: got error {}",
                    err
                );
            } else {
                // When bypassing the API BN, the replica responds with a reject.
                assert!(
                    matches!(err, AgentError::CertifiedReject { .. }),
                    "direct replica update for 'x' * 2**20: got error {}",
                    err
                );
            }
            let err = agent
                .query(&canister_id, &too_long_method_name)
                .call()
                .await
                .unwrap_err();

            if is_api_bn {
                // When going through the API BN, the request is rejected with HTTP 400 Bad Request.
                assert!(
                    matches!(err, AgentError::HttpError(ref payload) if payload.status == StatusCode::BAD_REQUEST.as_u16()),
                    "api bn update for 'x' * 2**20: got error {}",
                    err
                );
            } else {
                // When bypassing the API BN, the replica responds with a reject.
                assert!(
                    matches!(err, AgentError::UncertifiedReject { .. }),
                    "direct replica update for 'x' * 2**20: got error {}",
                    err
                );
            }

            let too_long_method_name = 'x'.to_string().repeat(3 << 20);
            let err = agent
                .update(&canister_id, &too_long_method_name)
                .call_and_wait()
                .await
                .unwrap_err();

            let payload_too_large = |err: AgentError| {
                match err {
                    AgentError::HttpError(payload) => {
                        assert_eq!(payload.status, StatusCode::PAYLOAD_TOO_LARGE.as_u16());
                    }
                    _ => panic!("Unexpected error: {:?}", err),
                };
            };

            if is_api_bn {
                // The API BN has more generous limits, so it still responds with HTTP 400 Bad Request.
                assert!(
                    matches!(err, AgentError::HttpError(ref payload) if payload.status == StatusCode::BAD_REQUEST.as_u16()),
                    "api bn update for 'x' * 3**20: got error {}",
                    err
                );
            } else {
                payload_too_large(err);
            }

            let err = agent
                .query(&canister_id, &too_long_method_name)
                .call()
                .await
                .unwrap_err();

            if is_api_bn {
                // When going through the API BN, the request is rejected with HTTP 400 Bad Request.
                assert!(
                    matches!(err, AgentError::HttpError(ref payload) if payload.status == StatusCode::BAD_REQUEST.as_u16()),
                    "api bn update for 'x' * 3**20: got error {}",
                    err
                );
            } else {
                // When bypassing the API BN, the replica responds with a reject.
                assert!(
                    matches!(err, AgentError::UncertifiedReject { .. }),
                    "direct replica update for 'x' * 3**20: got error {}",
                    err
                );
            }

            let too_long_method_name = 'x'.to_string().repeat(5 << 20);
            let err = agent
                .update(&canister_id, &too_long_method_name)
                .call_and_wait()
                .await
                .unwrap_err();
            payload_too_large(err);
            let err = agent
                .query(&canister_id, &too_long_method_name)
                .call()
                .await
                .unwrap_err();
            payload_too_large(err);
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

fn get_app_subnet_replica_url(snapshot: &TopologySnapshot) -> Url {
    let (_, app_subnet) = get_subnets(snapshot);
    let app_node = app_subnet.nodes().next().unwrap();
    app_node.get_public_url()
}

fn get_sys_subnet_replica_url(snapshot: &TopologySnapshot) -> Url {
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
            // User id
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
        .add_test(systest!(malformed_http_request))
        .add_test(systest!(method_name_edge_cases))
        .execute_from_args()?;

    Ok(())
}
