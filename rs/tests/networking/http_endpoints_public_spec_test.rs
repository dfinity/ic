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
1. Update call with canister_id A to the endpoint /api/v{2,3,4}/canister/B/call with a different canister ID B in the URL is rejected with 4xx;
2. Query call with canister_id A to the endpoint /api/v2/canister/B/query with a different canister ID B in the URL is rejected with 4xx;
3. Read state request for the path /canisters/A/controllers to the endpoints /api/{v2,v3}/canister/B/read_state with a different canister ID B in the URL is rejected with 4xx;
4. Read state request for the path /time to the endpoints /api/{v2,v3}/canister/aaaaa-aa/read_state is rejected with 4xx.

The different canister ID B is
1. The canister ID of a different canister on the same subnet;
2. The canister ID of a different canister on a different subnet;
3. A malformed principal;
4. The management canister ID.


end::catalog[] */

use anyhow::Result;
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
use ic_types::{
    CanisterId, PrincipalId,
    messages::{
        Blob, HttpCallContent, HttpCanisterUpdate, HttpQueryContent, HttpReadState,
        HttpReadStateContent, HttpRequestEnvelope, HttpUserQuery,
    },
    time::current_time,
};
use reqwest::{Response, StatusCode};
use slog::{Logger, debug, info};
use std::time::Duration;
use std::{collections::BTreeMap, net::SocketAddr};
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

fn endpoint_rejects_misrouted_requests(env: TestEnv, endpoint: Endpoint) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (_, app_subnet) = get_subnets(&snapshot);
    let app_node = app_subnet.nodes().next().unwrap();
    let principal_id = match endpoint {
        Endpoint::CanisterReadState(_) | Endpoint::Query(_) | Endpoint::Call(_) => {
            app_node.effective_canister_id()
        }
        Endpoint::SubnetReadState(_) => app_subnet.subnet_id.get(),
    };
    let node_url = app_node.get_public_url();
    let url = endpoint.url(node_url, principal_id);

    if !endpoint.is_compatible(&Endpoint::Call(Call::V4)) {
        let misrouted_request =
            Endpoint::Call(Call::V4).valid_request(app_node.effective_canister_id());
        info!(logger, "Sending a Call request to {url}");
        let status = block_on(send(url.clone(), misrouted_request, &logger));
        assert!(status.is_client_error(), "Should reject a Call request");
    }

    if !endpoint.is_compatible(&Endpoint::Query(query::Version::V3)) {
        let misrouted_request =
            Endpoint::Query(query::Version::V3).valid_request(app_node.effective_canister_id());
        info!(logger, "Sending a Query request to {url}");
        let status = block_on(send(url.clone(), misrouted_request, &logger));
        assert!(status.is_client_error(), "Should reject a Query request");
    }

    if !endpoint.is_compatible(&Endpoint::CanisterReadState(
        read_state::canister::Version::V3,
    )) {
        let misrouted_request = Endpoint::CanisterReadState(read_state::canister::Version::V3)
            .valid_request(app_node.effective_canister_id());
        info!(logger, "Sending a ReadState request to {url}");
        let status = block_on(send(url.clone(), misrouted_request, &logger));
        assert!(
            status.is_client_error(),
            "Should reject a ReadState request"
        );
    }
}

fn endpoint_rejects_requests_with_missing_fields(env: TestEnv, endpoint: Endpoint) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (_, app_subnet) = get_subnets(&snapshot);
    let app_node = app_subnet.nodes().next().unwrap();
    let principal_id = match endpoint {
        Endpoint::CanisterReadState(_) | Endpoint::Query(_) | Endpoint::Call(_) => {
            app_node.effective_canister_id()
        }
        Endpoint::SubnetReadState(_) => app_subnet.subnet_id.get(),
    };
    let node_url = app_node.get_public_url();
    let url = endpoint.url(node_url, principal_id);
    let valid_request = endpoint.valid_request(principal_id);

    let deserialized_envelope: BTreeMap<serde_cbor::Value, serde_cbor::Value> =
        serde_cbor::from_slice(&valid_request).unwrap();
    let serde_cbor::Value::Map(deserialized_content) = deserialized_envelope
        .get(&serde_cbor::Value::Text(String::from("content")))
        .unwrap()
    else {
        unreachable!()
    };
    for field_name in deserialized_content.keys() {
        let mut request_with_the_field_missing = deserialized_content.clone();
        request_with_the_field_missing.remove(field_name);
        let serde_cbor::Value::Text(field_name) = field_name else {
            unreachable!()
        };
        info!(
            logger,
            "Sending a request with `{field_name}` missing to `{url}`"
        );
        let content = serde_cbor::to_vec(&request_with_the_field_missing).unwrap();

        let deserialized: BTreeMap<serde_cbor::Value, serde_cbor::Value> =
            serde_cbor::from_slice(&content).unwrap();
        let envelope = serde_cbor::to_vec(&BTreeMap::from([(
            serde_cbor::Value::Text(String::from("content")),
            serde_cbor::Value::Map(deserialized),
        )]))
        .unwrap();

        let status = block_on(send(url.clone(), envelope, &logger));

        // nonce is the only optional field
        if field_name != "nonce" {
            assert!(
                status.is_client_error(),
                "Should reject a request with `{field_name}` missing"
            );
        } else {
            assert!(
                status.is_success(),
                "Should accept a request with `{field_name}` missing"
            );
        }
    }
}

fn endpoint_rejects_requests_with_empty_sender(env: TestEnv, endpoint: Endpoint) {
    let logger = env.logger();
    let snapshot = env.topology_snapshot();
    let (_, app_subnet) = get_subnets(&snapshot);
    let app_node = app_subnet.nodes().next().unwrap();
    let principal_id = match endpoint {
        Endpoint::CanisterReadState(_) | Endpoint::Query(_) | Endpoint::Call(_) => {
            app_node.effective_canister_id()
        }
        Endpoint::SubnetReadState(_) => app_subnet.subnet_id.get(),
    };
    let node_url = app_node.get_public_url();
    let url = endpoint.url(node_url, principal_id);
    let request_with_empty_sender = endpoint.request_with_sender(principal_id, Blob(vec![]));

    let status = block_on(send(url.clone(), request_with_empty_sender, &logger));
    assert!(
        status.is_client_error(),
        "Requests with empty sender field should fail"
    );
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

#[derive(Copy, Clone, Debug)]
enum Endpoint {
    CanisterReadState(read_state::canister::Version),
    SubnetReadState(read_state::subnet::Version),
    Query(query::Version),
    Call(Call),
}

impl Endpoint {
    fn variants() -> &'static [Endpoint] {
        &[
            Endpoint::CanisterReadState(read_state::canister::Version::V2),
            Endpoint::CanisterReadState(read_state::canister::Version::V3),
            Endpoint::SubnetReadState(read_state::subnet::Version::V2),
            Endpoint::SubnetReadState(read_state::subnet::Version::V3),
            Endpoint::Query(query::Version::V2),
            Endpoint::Query(query::Version::V3),
            Endpoint::Call(Call::V2),
            Endpoint::Call(Call::V3),
            Endpoint::Call(Call::V4),
        ]
    }

    /// Returns `true` iff the endpoints accept the same types of requests.
    fn is_compatible(&self, other: &Endpoint) -> bool {
        match (self, other) {
            (Endpoint::Query(_), Endpoint::Query(_)) => true,
            (Endpoint::Call(_), Endpoint::Call(_)) => true,
            (
                Endpoint::CanisterReadState(_) | Endpoint::SubnetReadState(_),
                Endpoint::CanisterReadState(_) | Endpoint::SubnetReadState(_),
            ) => true,
            _ => false,
        }
    }

    fn url(&self, base: Url, principal_id: PrincipalId) -> Url {
        match self {
            Endpoint::CanisterReadState(read_state::canister::Version::V2) => {
                base.join(&format!("/api/v2/canister/{principal_id}/read_state"))
            }
            Endpoint::CanisterReadState(read_state::canister::Version::V3) => {
                base.join(&format!("/api/v3/canister/{principal_id}/read_state"))
            }
            Endpoint::SubnetReadState(read_state::subnet::Version::V2) => {
                base.join(&format!("/api/v2/subnet/{principal_id}/read_state"))
            }
            Endpoint::SubnetReadState(read_state::subnet::Version::V3) => {
                base.join(&format!("/api/v3/subnet/{principal_id}/read_state"))
            }
            Endpoint::Query(query::Version::V2) => {
                base.join(&format!("/api/v2/canister/{principal_id}/query"))
            }
            Endpoint::Query(query::Version::V3) => {
                base.join(&format!("/api/v3/canister/{principal_id}/query"))
            }
            Endpoint::Call(Call::V2) => base.join(&format!("/api/v2/canister/{principal_id}/call")),
            Endpoint::Call(Call::V3) => base.join(&format!("/api/v3/canister/{principal_id}/call")),
            Endpoint::Call(Call::V4) => base.join(&format!("/api/v4/canister/{principal_id}/call")),
        }
        .unwrap()
    }

    fn valid_request(&self, principal_id: PrincipalId) -> Vec<u8> {
        let anonymous_sender = Blob(PrincipalId::new_anonymous().into_vec());

        self.request_with_sender(principal_id, anonymous_sender)
    }

    fn request_with_sender(&self, principal_id: PrincipalId, sender: Blob) -> Vec<u8> {
        let ingress_expiry = (current_time() + Duration::from_secs(60)).as_nanos_since_unix_epoch();
        let nonce = Some(Blob(vec![1, 2, 3]));

        match self {
            Endpoint::Query(_) => unsigned_envelope(HttpQueryContent::Query {
                query: HttpUserQuery {
                    canister_id: Blob(principal_id.into_vec()),
                    method_name: String::from("method_name"),
                    arg: Blob(vec![]),
                    sender,
                    ingress_expiry,
                    nonce,
                },
            }),
            Endpoint::Call(_) => unsigned_envelope(HttpCallContent::Call {
                update: HttpCanisterUpdate {
                    canister_id: Blob(principal_id.into_vec()),
                    method_name: String::from("method_name"),
                    arg: Blob(vec![]),
                    ingress_expiry,
                    sender,
                    nonce,
                },
            }),
            Endpoint::CanisterReadState(_) | Endpoint::SubnetReadState(_) => {
                unsigned_envelope(HttpReadStateContent::ReadState {
                    read_state: HttpReadState {
                        paths: vec![],
                        sender,
                        ingress_expiry,
                        nonce,
                    },
                })
            }
        }
    }
}

fn unsigned_envelope<C: serde::ser::Serialize>(content: C) -> Vec<u8> {
    let envelope = HttpRequestEnvelope {
        content,
        sender_pubkey: None,
        sender_sig: None,
        sender_delegation: None,
    };

    serde_cbor::to_vec(&envelope).unwrap()
}

async fn send(url: Url, body: Vec<u8>, logger: &Logger) -> StatusCode {
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = client
        .post(url)
        .header("Content-Type", "application/cbor")
        .body(body)
        .send()
        .await
        .unwrap();

    let status = response.status();
    info!(logger, "Replica responded with status code {status}");

    if !status.is_success() {
        let error = response.bytes().await.unwrap();

        debug!(logger, "Replica responded with error: {error:?}");
    }

    status
}

macro_rules! systest_all_variants {
    ($group: expr, $function_name:path) => {
        for endpoint in Endpoint::variants() {
            $group = $group.add_test(systest!($function_name; *endpoint));
        }
    };
}

fn main() -> Result<()> {
    let mut group = SystemTestGroup::new()
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
        .add_test(systest!(read_time; read_state::canister::Version::V3));

    systest_all_variants!(group, endpoint_rejects_requests_with_missing_fields);
    systest_all_variants!(group, endpoint_rejects_misrouted_requests);
    systest_all_variants!(group, endpoint_rejects_requests_with_empty_sender);

    group.execute_from_args()?;

    Ok(())
}
