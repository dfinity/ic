#![cfg(unix)]

use crate::common::frontend_canister;
use candid::{CandidType, Decode, Deserialize, Encode, Principal, decode_one, encode_one};
use ic_base_types::{PrincipalId, SubnetId};
use ic_management_canister_types::{
    HttpRequestResult, NodeMetricsHistoryArgs, NodeMetricsHistoryRecord,
};
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::node_operator::NodeOperatorRegistry;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_transport::pb::v1::RegistryGetLatestVersionResponse;
use pocket_ic::common::rest::{
    CreateInstanceResponse, ExtendedSubnetConfigSet, IcpFeatures, IcpFeaturesConfig,
    IncompleteStateFlag, InstanceConfig, InstanceHttpGatewayConfig,
};
use pocket_ic::nonblocking::PocketIc as PocketIcAsync;
use pocket_ic::{
    PocketIc, PocketIcBuilder, PocketIcState, StartServerParams, SubnetBlockmakers, TickConfigs,
    start_server, update_candid_as,
};
use prost::Message;
use registry_canister::mutations::do_add_node_operator::AddNodeOperatorPayload;
use registry_canister::mutations::do_remove_node_operators::{
    NodeOperatorPrincipals, RemoveNodeOperatorsPayload,
};
use reqwest::StatusCode;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime},
};
use tempfile::TempDir;

mod common;

// 2T cycles
const INIT_CYCLES: u128 = 2_000_000_000_000;

#[derive(CandidType, Deserialize, Debug)]
enum RejectionCode {
    NoError,
    SysFatal,
    SysTransient,
    DestinationInvalid,
    CanisterReject,
    CanisterError,
    Unknown,
}

fn test_canister_wasm() -> Vec<u8> {
    let wasm_path = std::env::var_os("TEST_WASM").expect("Missing test canister wasm file");
    std::fs::read(wasm_path).unwrap()
}

async fn resume_killed_instance_impl(
    incomplete_state: Option<IncompleteStateFlag>,
) -> Result<(), String> {
    let (mut server, server_url) = start_server(StartServerParams::default()).await;
    let temp_dir = TempDir::new().unwrap();

    let state = PocketIcState::new_from_path(temp_dir.path().to_path_buf());
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_server_url(server_url)
        .with_state(state)
        .build_async()
        .await;

    let canister_id = pic.create_canister().await;

    // Execute sufficiently many rounds to trigger a checkpoint.
    let expected_checkpoint_height = 500;
    for _ in 0..expected_checkpoint_height {
        pic.tick().await;
    }

    // Wait until the checkpoint is written to disk.
    let topology = pic.topology().await;
    let subnet_id = topology.get_app_subnets()[0];
    let subnet_seed = hex::encode(topology.subnet_configs.get(&subnet_id).unwrap().subnet_seed);
    let expected_checkpoint_dir = temp_dir
        .path()
        .join(subnet_seed)
        .join("checkpoints")
        .join(format!("{expected_checkpoint_height:016x}"));
    let start = Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(300) {
            panic!("Timed out waiting for a checkpoint to be written to disk.");
        }
        // Check if the expected checkpoint dir exists and does not contain the "unverified checkpoint marker".
        if std::fs::read_dir(&expected_checkpoint_dir).is_ok() {
            let unverified_checkpoint_marker =
                expected_checkpoint_dir.join("unverified_checkpoint_marker");
            if !unverified_checkpoint_marker.is_file() {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // The following (most recent) changes will be lost after killing the instance.
    let now = SystemTime::now();
    pic.set_certified_time(now.into()).await;
    let another_canister_id = pic.create_canister().await;

    assert!(pic.canister_exists(canister_id).await);
    assert!(pic.canister_exists(another_canister_id).await);
    let time = pic.get_time().await;
    assert!(time >= now.into());

    server.kill().unwrap();

    let (_, server_url) = start_server(StartServerParams::default()).await;
    let client = reqwest::Client::new();
    let instance_config = InstanceConfig {
        subnet_config_set: ExtendedSubnetConfigSet::default(),
        http_gateway_config: None,
        state_dir: Some(temp_dir.path().to_path_buf()),
        icp_config: None,
        log_level: None,
        bitcoind_addr: None,
        dogecoind_addr: None,
        icp_features: None,
        incomplete_state,
        initial_time: None,
    };
    let response = client
        .post(server_url.join("instances").unwrap())
        .json(&instance_config)
        .send()
        .await
        .unwrap();
    if !response.status().is_success() {
        return Err(response.text().await.unwrap());
    }
    let instance_id = match response.json::<CreateInstanceResponse>().await.unwrap() {
        CreateInstanceResponse::Created { instance_id, .. } => instance_id,
        CreateInstanceResponse::Error { message } => panic!("Unexpected error: {message}"),
    };
    let pic = PocketIcAsync::new_from_existing_instance(server_url, instance_id, None);

    // Only the first canister (created before the last checkpoint) is preserved,
    // the other canister and time change are lost.
    assert!(pic.canister_exists(canister_id).await);
    assert!(!pic.canister_exists(another_canister_id).await);
    let resumed_time = pic.get_time().await;
    assert!(resumed_time < now.into());

    // Drop instance explicitly to prevent data races in the StateManager.
    pic.drop().await;

    Ok(())
}

// Killing the PocketIC server inside WSL is challenging => skipping this test on Windows.
#[tokio::test]
async fn resume_killed_instance_default() {
    let err = resume_killed_instance_impl(None).await.unwrap_err();
    assert!(err.contains("The state of subnet with seed 7712b2c09cb96b3aa3fbffd4034a21a39d5d13f80e043161d1d71f4c593434af is incomplete."));
}

// Killing the PocketIC server inside WSL is challenging => skipping this test on Windows.
#[tokio::test]
async fn resume_killed_instance_strict() {
    let err = resume_killed_instance_impl(Some(IncompleteStateFlag::Disabled))
        .await
        .unwrap_err();
    assert!(err.contains("The state of subnet with seed 7712b2c09cb96b3aa3fbffd4034a21a39d5d13f80e043161d1d71f4c593434af is incomplete."));
}

// Killing the PocketIC server inside WSL is challenging => skipping this test on Windows.
#[tokio::test]
async fn resume_killed_instance() {
    resume_killed_instance_impl(Some(IncompleteStateFlag::Enabled))
        .await
        .unwrap();
}

struct HttpServer {
    addr: SocketAddr,
    flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl HttpServer {
    fn new(bind_addr: &str) -> Self {
        fn handle_connection(mut stream: TcpStream) {
            let mut buffer = [0; 1024];
            let _ = stream.read(&mut buffer).unwrap();

            let status_line = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
            let body = "Hello from dynamic-port Rust server!";
            let response = format!("{status_line}{body}");

            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        }

        let flag = Arc::new(AtomicBool::new(true));

        // Bind to port 0 (OS assigns a free port)
        let listener = TcpListener::bind(format!("{bind_addr}:0")).expect("Failed to bind");

        // We use non-blocking mode here to gracefully shutdown if `flag` becomes `false`.
        listener.set_nonblocking(true).unwrap();

        // Extract the assigned bind address
        let addr = listener.local_addr().unwrap();

        let flag_in_thread = flag.clone();
        let handle = std::thread::spawn(move || {
            while flag_in_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // Convert this connection to blocking mode.
                        stream.set_nonblocking(false).unwrap();
                        handle_connection(stream);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // No incoming connection; sleep briefly and retry
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => {
                        panic!("Unexpected error: {e}");
                    }
                }
            }
        });

        Self {
            addr,
            flag,
            handle: Some(handle),
        }
    }

    fn addr(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Relaxed);
        self.handle.take().unwrap().join().unwrap();
    }
}

// This test does not work on Windows since the test HTTP webserver is spawned by the test driver
// on the Windows host while the PocketIC server (making the canister HTTP outcall) runs in WSL.
#[test]
fn test_canister_http_in_live_mode() {
    // We create a PocketIC instance with an NNS subnet
    // (the "live" mode requires the NNS subnet).
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // Enable the "live" mode.
    pic.make_live(None);

    let http_server = HttpServer::new("127.0.0.1");

    // Create a canister and charge it with 2T cycles.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);

    // Install the test canister wasm file on the canister.
    let test_wasm = test_canister_wasm();
    pic.install_canister(canister_id, test_wasm, vec![], None);

    // Submit an update call to the test canister making a canister http outcall.
    let call_id = pic
        .submit_call(
            canister_id,
            Principal::anonymous(),
            "canister_http",
            encode_one(http_server.addr()).unwrap(),
        )
        .unwrap();

    // Await the update call without making additional progress (the PocketIC instance
    // is already in the "live" mode making progress automatically).
    let reply = pic.await_call_no_ticks(call_id).unwrap();
    let http_response: Result<HttpRequestResult, (RejectionCode, String)> =
        decode_one(&reply).unwrap();
    http_response.unwrap();
}

#[test]
fn test_raw_gateway() {
    // We create a PocketIC instance consisting of the NNS and one application subnet.
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // We retrieve the app subnet ID from the topology.
    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];

    // We create a canister on the app subnet.
    let canister = pic.create_canister_on_subnet(None, None, app_subnet);
    assert_eq!(pic.get_subnet(canister), Some(app_subnet));

    // We top up the canister with cycles and install the test canister WASM to them.
    pic.add_cycles(canister, INIT_CYCLES);
    pic.install_canister(canister, test_canister_wasm(), vec![], None);

    // We start the HTTP gateway
    pic.make_live(None);

    // We make two requests: the non-raw request fails because the test canister does not certify its response,
    // the raw request succeeds.
    for (raw, expected) in [
        (
            false,
            "The response from the canister failed verification and cannot be trusted.",
        ),
        (true, "My sample asset."),
    ] {
        let (client, url) = frontend_canister(&pic, canister, raw, "/asset.txt");
        let res = client.get(url).send().unwrap();
        let page = String::from_utf8(res.bytes().unwrap().to_vec()).unwrap();
        assert!(page.contains(expected));
    }
}

#[test]
fn test_custom_blockmaker_metrics() {
    const HOURS_IN_SECONDS: u64 = 60 * 60;

    // Create a temporary state directory from which the test can retrieve the registry.
    let state_dir = TempDir::new().unwrap();
    let state_dir_path_buf = state_dir.path().to_path_buf();

    let pocket_ic = PocketIcBuilder::new()
        .with_state_dir(state_dir_path_buf.clone())
        .with_application_subnet()
        .build();
    let topology = pocket_ic.topology();
    let application_subnet = topology.get_app_subnets()[0];

    // Create and install test canister.
    let canister = pocket_ic.create_canister_on_subnet(None, None, application_subnet);
    pocket_ic.add_cycles(canister, INIT_CYCLES);
    pocket_ic.install_canister(canister, test_canister_wasm(), vec![], None);

    // Retrieve node ids from the registry
    let registry_proto_path = state_dir_path_buf.join("registry.proto");
    let registry_data_provider = Arc::new(ProtoRegistryDataProvider::load_from_file(
        registry_proto_path,
    ));
    let latest_version = registry_data_provider.latest_version();
    let registry_client = RegistryClientImpl::new(registry_data_provider.clone(), None);
    registry_client.poll_once().unwrap();
    let node_ids = registry_client
        .get_node_ids_on_subnet(
            SubnetId::new(PrincipalId(application_subnet)),
            latest_version,
        )
        .unwrap()
        .unwrap();

    let blockmaker_1 = node_ids[0].get().0;
    let blockmaker_2 = node_ids[1].get().0;

    let blockmakers = vec![SubnetBlockmakers {
        subnet: application_subnet,
        blockmaker: blockmaker_1,
        failed_blockmakers: vec![blockmaker_2],
    }];

    let tick_configs = TickConfigs {
        blockmakers: Some(blockmakers),
        first_subnet: None,
        last_subnet: None,
    };
    let daily_blocks = 5;

    // Blockmaker metrics are recorded in the management canister
    for _ in 0..daily_blocks {
        pocket_ic.tick_with_configs(tick_configs.clone());
    }
    // Advance time until next day so that management canister can record blockmaker metrics
    pocket_ic.advance_time(std::time::Duration::from_secs(HOURS_IN_SECONDS * 24));
    pocket_ic.tick();

    let response = pocket_ic
        .update_call(
            canister,
            Principal::anonymous(),
            // Calls the node_metrics_history method on the management canister
            "node_metrics_history_proxy",
            Encode!(&NodeMetricsHistoryArgs {
                subnet_id: application_subnet,
                start_at_timestamp_nanos: 0,
            })
            .unwrap(),
        )
        .unwrap();

    let first_node_metrics = Decode!(&response, Vec<NodeMetricsHistoryRecord>)
        .unwrap()
        .remove(0)
        .node_metrics;

    let blockmaker_1_metrics = first_node_metrics
        .iter()
        .find(|x| x.node_id == blockmaker_1)
        .unwrap()
        .clone();
    let blockmaker_2_metrics = first_node_metrics
        .into_iter()
        .find(|x| x.node_id == blockmaker_2)
        .unwrap();

    assert_eq!(blockmaker_1_metrics.num_blocks_proposed_total, daily_blocks);
    assert_eq!(blockmaker_1_metrics.num_block_failures_total, 0);

    assert_eq!(blockmaker_2_metrics.num_blocks_proposed_total, 0);
    assert_eq!(blockmaker_2_metrics.num_block_failures_total, daily_blocks);
}

// This test times out on Windows.
#[test]
fn payload_too_large() {
    let http_gateway_config = InstanceHttpGatewayConfig {
        ip_addr: None,
        port: None,
        domains: None,
        https_config: None,
    };
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_http_gateway(http_gateway_config)
        .build();

    // Valid canister ID.
    let canister_id = pic.create_canister();

    // Too large API requests via /instances API and proxied through HTTP gateway.
    let instances_url = format!(
        "{}instances/{}/api/v2/canister/{}/read_state",
        pic.get_server_url(),
        pic.instance_id(),
        canister_id,
    );
    let gateway_url = format!(
        "{}api/v2/canister/{}/read_state",
        pic.url().unwrap(),
        canister_id,
    );
    for url in [instances_url, gateway_url] {
        let client = reqwest::blocking::Client::new();
        retry_send_too_large_body(&client, &url, StatusCode::PAYLOAD_TOO_LARGE);
    }

    // Too large frontend request for canister via HTTP gateway.
    let (client, url) = frontend_canister(&pic, canister_id, false, "/index.html");
    retry_send_too_large_body(&client, url.as_ref(), StatusCode::SERVICE_UNAVAILABLE);
}

fn retry_send_too_large_body(
    client: &reqwest::blocking::Client,
    url: &str,
    expected_status: StatusCode,
) {
    let started = Instant::now();
    while let Err(err) = send_too_large_body(client, url, expected_status) {
        println!("{err}");

        if started.elapsed() > Duration::from_secs(5 * 60) {
            panic!("Retrying requests with too large body timed out.");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn send_too_large_body(
    client: &reqwest::blocking::Client,
    url: &str,
    expected_status: StatusCode,
) -> Result<(), String> {
    let resp = client
        .post(url)
        .body(vec![42; 5 * 1024 * 1024])
        .send()
        .map_err(|err| format!("Failed to send request: {err}"))?;

    if resp.status() != expected_status {
        return Err(format!("Unexpected status code: {:?}", resp.status()));
    }

    Ok(())
}

#[test]
fn test_registry_sync() {
    let registry_canister_id = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
    let governance_canister_id = Principal::from_text("rrkah-fqaaa-aaaaa-aaaaq-cai").unwrap();

    // Create a temporary state directory from which the test can retrieve PocketIC registry.
    let state_dir = TempDir::new().unwrap();
    let state_dir_path_buf = state_dir.path().to_path_buf();

    let icp_features = IcpFeatures {
        registry: Some(IcpFeaturesConfig::DefaultConfig),
        ..Default::default()
    };
    let pocket_ic = PocketIcBuilder::new()
        .with_state_dir(state_dir_path_buf.clone())
        .with_icp_features(icp_features)
        .build();

    let latest_pocketic_registry_version = || {
        let registry_proto_path = state_dir_path_buf.join("registry.proto");
        let registry_data_provider = Arc::new(ProtoRegistryDataProvider::load_from_file(
            registry_proto_path,
        ));
        registry_data_provider.latest_version().get()
    };

    let latest_canister_registry_version = |pocket_ic: &PocketIc| {
        let empty_vector_pbuf = vec![0x0a, 0x00];
        let res = pocket_ic
            .update_call(
                registry_canister_id,
                Principal::anonymous(),
                "get_latest_version",
                empty_vector_pbuf,
            )
            .unwrap();
        RegistryGetLatestVersionResponse::decode(res.as_slice())
            .unwrap()
            .version
    };

    let check_registry_versions = |pocket_ic: &PocketIc, expected_registry_version: u64| {
        assert_eq!(
            latest_pocketic_registry_version(),
            expected_registry_version
        );
        assert_eq!(
            latest_canister_registry_version(pocket_ic),
            expected_registry_version
        );
    };

    let get_node_operator_record = |node_operator_id: PrincipalId| {
        let registry_proto_path = state_dir_path_buf.join("registry.proto");
        let registry_data_provider = Arc::new(ProtoRegistryDataProvider::load_from_file(
            registry_proto_path,
        ));
        let registry_client = RegistryClientImpl::new(registry_data_provider.clone(), None);
        registry_client.poll_once().unwrap();
        registry_client
            .get_node_operator_record(node_operator_id, registry_data_provider.latest_version())
            .unwrap()
    };

    // Initially the latest registry version in PocketIC registry and the registry canister match.
    let initial_registry_version = latest_pocketic_registry_version();
    check_registry_versions(&pocket_ic, initial_registry_version);

    // We update the registry in the registry canister
    // by creating a new node operator in the registry.
    let node_operator_principal_id = PrincipalId(Principal::from_slice(&[42; 29]));
    let node_provider_principal_id = Principal::from_slice(&[64; 29]);
    assert!(get_node_operator_record(node_operator_principal_id).is_none());
    let add_node_operator_payload = AddNodeOperatorPayload {
        ipv6: None,
        node_operator_principal_id: Some(node_operator_principal_id),
        node_allowance: 42,
        rewardable_nodes: BTreeMap::new(),
        node_provider_principal_id: Some(PrincipalId(node_provider_principal_id)),
        dc_id: "zh".to_string(),
        max_rewardable_nodes: None,
    };
    update_candid_as::<_, ()>(
        &pocket_ic,
        registry_canister_id,
        governance_canister_id,
        "add_node_operator",
        (add_node_operator_payload,),
    )
    .unwrap();
    assert!(get_node_operator_record(node_operator_principal_id).is_some());

    // The latest registry version in both PocketIC and the registry canister should increase by one.
    check_registry_versions(&pocket_ic, initial_registry_version + 1);

    // We update the registry in PocketIC
    // by creating a new subnet in the registry.
    let specified_id = Principal::from_text("mxzaz-hqaaa-aaaar-qaada-cai").unwrap(); // ckBTC ledger => fiduciary subnet
    let topology = pocket_ic.topology();
    assert!(topology.get_fiduciary().is_none()); // fiduciary subnet does not exist initially
    pocket_ic
        .create_canister_with_id(None, None, specified_id)
        .unwrap();
    let topology = pocket_ic.topology();
    assert!(topology.get_fiduciary().is_some()); // fiduciary subnet was created (also in the registry)

    // The latest registry version in both PocketIC and the registry canister should increase by one.
    check_registry_versions(&pocket_ic, initial_registry_version + 2);

    // We test if registry in both PocketIC and the registry canister is properly restored
    // when creating a new PocketIC instance from the existing state.
    let state = pocket_ic.drop_and_take_state().unwrap();
    let pocket_ic = PocketIcBuilder::new().with_state(state).build();

    // The latest registry version in both PocketIC and the registry canister should be as before.
    check_registry_versions(&pocket_ic, initial_registry_version + 2);

    // We update the registry in the registry canister
    // by removing the node operator from the registry.
    // In particular, we test syncing registry key deletion.
    assert!(get_node_operator_record(node_operator_principal_id).is_some());
    let remove_node_operators_payload = RemoveNodeOperatorsPayload {
        node_operators_to_remove: vec![], // legacy field
        node_operator_principals_to_remove: Some(NodeOperatorPrincipals {
            principals: vec![node_operator_principal_id],
        }),
    };
    update_candid_as::<_, ()>(
        &pocket_ic,
        registry_canister_id,
        governance_canister_id,
        "remove_node_operators",
        (remove_node_operators_payload,),
    )
    .unwrap();
    assert!(get_node_operator_record(node_operator_principal_id).is_none());

    // The latest registry version in both PocketIC and the registry canister should increase by one.
    check_registry_versions(&pocket_ic, initial_registry_version + 3);
}
