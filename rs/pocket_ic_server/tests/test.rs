mod common;

use crate::common::raw_canister_id_range_into;
use candid::{Encode, Principal};
use ic_agent::agent::{http_transport::ReqwestTransport, CallResponse};
use ic_cdk::api::management_canister::main::CanisterIdRecord;
use ic_cdk::api::management_canister::provisional::ProvisionalCreateCanisterWithCyclesArgument;
use ic_interfaces_registry::{
    RegistryDataProvider, RegistryVersionedRecord, ZERO_REGISTRY_VERSION,
};
use ic_management_canister_types::ProvisionalCreateCanisterWithCyclesArgs;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_transport::pb::v1::{
    registry_mutation::Type, RegistryAtomicMutateRequest, RegistryMutation,
};
use ic_utils::interfaces::ManagementCanister;
use pocket_ic::common::rest::{
    CreateHttpGatewayResponse, HttpGatewayBackend, HttpGatewayConfig, HttpGatewayDetails,
    HttpsConfig, InstanceConfig, SubnetConfigSet,
};
use pocket_ic::{update_candid, PocketIc, PocketIcBuilder, WasmResult};
use rcgen::{CertificateParams, KeyPair};
use registry_canister::init::RegistryCanisterInitPayload;
use reqwest::blocking::Client;
use reqwest::Client as NonblockingClient;
use reqwest::{StatusCode, Url};
use slog::Level;
use std::io::Read;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};

pub const LOCALHOST: &str = "127.0.0.1";

fn start_server_helper(
    parent_pid: Option<u32>,
    capture_stdout: bool,
    capture_stderr: bool,
) -> (Url, Child) {
    let bin_path = std::env::var_os("POCKET_IC_BIN").expect("Missing PocketIC binary");
    let port_file_path = if let Some(parent_pid) = parent_pid {
        std::env::temp_dir().join(format!("pocket_ic_{}.port", parent_pid))
    } else {
        NamedTempFile::new().unwrap().into_temp_path().to_path_buf()
    };
    let mut cmd = Command::new(PathBuf::from(bin_path));
    if let Some(parent_pid) = parent_pid {
        cmd.arg("--pid").arg(parent_pid.to_string());
    } else {
        cmd.arg("--port-file").arg(port_file_path.clone());
    }
    // use a long TTL of 5 mins (the bazel test timeout for medium tests)
    // so that the server doesn't die during the test if the runner
    // is overloaded
    cmd.arg("--ttl").arg("300");
    if capture_stdout {
        cmd.stdout(std::process::Stdio::piped());
    }
    if capture_stderr {
        cmd.stderr(std::process::Stdio::piped());
    }
    let out = cmd.spawn().expect("Failed to start PocketIC binary");
    let url = loop {
        if let Ok(port_string) = std::fs::read_to_string(port_file_path.clone()) {
            if port_string.contains("\n") {
                let port: u16 = port_string
                    .trim_end()
                    .parse()
                    .expect("Failed to parse port to number");
                break Url::parse(&format!("http://{}:{}/", LOCALHOST, port)).unwrap();
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    (url, out)
}

pub fn start_server() -> Url {
    let parent_pid = std::os::unix::process::parent_id();
    start_server_helper(Some(parent_pid), false, false).0
}

#[test]
fn test_status() {
    let url = start_server();
    let client = Client::new();

    let response = client.get(url.join("status/").unwrap()).send().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn test_creation_of_instance_extended() {
    let url = start_server();
    let client = Client::new();
    let instance_config = InstanceConfig {
        subnet_config_set: SubnetConfigSet {
            application: 1,
            ..Default::default()
        }
        .into(),
        state_dir: None,
        nonmainnet_features: false,
        log_level: None,
    };
    let response = client
        .post(url.join("instances").unwrap())
        .json(&instance_config)
        .send()
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(!response.text().unwrap().is_empty());
}

#[test]
fn test_blob_store() {
    let url = start_server();
    let client = Client::new();
    let blob_1 = "decafbad".as_bytes();
    let blob_2 = "deadbeef".as_bytes();

    let response = client
        .post(url.join("blobstore/").unwrap())
        .body(blob_1)
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let blob_id_1 = response.text().unwrap();

    let response = client
        .post(url.join("blobstore/").unwrap())
        .body(blob_2)
        .header(reqwest::header::CONTENT_ENCODING, "gzip")
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let blob_id_2 = response.text().unwrap();

    let response = client
        .get(url.join(&format!("blobstore/{blob_id_1}")).unwrap())
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    assert!(response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .is_none());

    let blob = response.bytes().unwrap();
    assert_eq!(blob, "decafbad".as_bytes());

    let response = client
        .get(url.join(&format!("blobstore/{blob_id_2}")).unwrap())
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let header = response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .unwrap()
        .as_bytes();
    assert_eq!(header, b"gzip");

    let blob = response.bytes().unwrap();
    assert_eq!(blob, "deadbeef".as_bytes());

    let nonexistent_blob_id = "does not exist".to_owned();
    let response = client
        .get(
            url.join(&format!("blobstore/{nonexistent_blob_id}"))
                .unwrap(),
        )
        .send()
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn test_blob_store_wrong_encoding() {
    let url = start_server();
    let client = Client::new();
    let blob = "decafbad".as_bytes();

    let response = client
        .post(url.join("blobstore/").unwrap())
        .body(blob)
        .header(reqwest::header::CONTENT_ENCODING, "bad_encoding")
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response
        .text()
        .unwrap()
        .to_lowercase()
        .contains("bad encoding"));
}

#[test]
fn test_port_file() {
    // tests the port file by setting the parent PID to None in start_server_helper
    start_server_helper(None, false, false);
}

async fn test_gateway(server_url: Url, https: bool) {
    // create PocketIC instance
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build_async()
        .await;

    // retrieve the first canister ID on the application subnet
    // which will be the effective and expected canister ID for canister creation
    let topology = pic.topology().await;
    let app_subnet = topology.get_app_subnets()[0];
    let effective_canister_id =
        raw_canister_id_range_into(&topology.0.get(&app_subnet).unwrap().canister_ranges[0]).start;

    // define HTTP protocol for this test
    let proto = if https { "https" } else { "http" };

    // define two domains for canister ID resolution
    let localhost = "localhost";
    let sub_localhost = &format!("{}.{}", effective_canister_id, localhost);
    let alt_domain = "example.com";
    let sub_alt_domain = &format!("{}.{}", effective_canister_id, alt_domain);

    // generate root TLS certificate (only used if `https` is set to `true`,
    // but defining it here unconditionally simplifies the test)
    let root_key_pair = KeyPair::generate().unwrap();
    let root_cert = CertificateParams::new(vec![
        localhost.to_string(),
        sub_localhost.to_string(),
        alt_domain.to_string(),
        sub_alt_domain.to_string(),
    ])
    .unwrap()
    .self_signed(&root_key_pair)
    .unwrap();
    let (mut cert_file, cert_path) = NamedTempFile::new().unwrap().keep().unwrap();
    cert_file.write_all(root_cert.pem().as_bytes()).unwrap();
    let (mut key_file, key_path) = NamedTempFile::new().unwrap().keep().unwrap();
    key_file
        .write_all(root_key_pair.serialize_pem().as_bytes())
        .unwrap();

    // make PocketIc instance live with an HTTP gateway
    let domains = Some(vec![localhost.to_string(), alt_domain.to_string()]);
    let https_config = if https {
        Some(HttpsConfig {
            cert_path: cert_path.into_os_string().into_string().unwrap(),
            key_path: key_path.into_os_string().into_string().unwrap(),
        })
    } else {
        None
    };
    let port = pic
        .make_live_with_params(None, domains.clone(), https_config.clone())
        .await
        .port_or_known_default()
        .unwrap();

    // check that an HTTP gateway with the matching port is returned when listing all HTTP gateways
    // and its details are set properly
    let client = NonblockingClient::new();
    let http_gateways: Vec<HttpGatewayDetails> = client
        .get(server_url.join("http_gateway").unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let http_gateway_details = http_gateways
        .into_iter()
        .find(|details| details.port == port)
        .unwrap();
    assert_eq!(
        http_gateway_details.forward_to,
        HttpGatewayBackend::PocketIcInstance(pic.instance_id)
    );
    assert_eq!(http_gateway_details.domains, domains);
    assert_eq!(http_gateway_details.https_config, https_config);

    // create a non-blocking reqwest client resolving localhost/example.com and <canister-id>.localhost/example.com to [::1]
    let mut builder = NonblockingClient::builder()
        .resolve(
            localhost,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        )
        .resolve(
            sub_localhost,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        )
        .resolve(
            alt_domain,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        )
        .resolve(
            sub_alt_domain,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        );
    // add a custom root certificate
    if https {
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(root_cert.pem().as_bytes()).unwrap(),
        );
    }
    let client = builder.build().unwrap();

    // create agent with custom transport
    let transport = ReqwestTransport::create_with_client(
        format!("{}://{}:{}", proto, localhost, port),
        client.clone(),
    )
    .unwrap();
    let agent = ic_agent::Agent::builder()
        .with_transport(transport)
        .build()
        .unwrap();
    agent.fetch_root_key().await.unwrap();

    // deploy II canister to PocketIC instance using agent and proxying through HTTP(S) gateway
    let ic00 = ManagementCanister::create(&agent);
    let (canister_id,) = ic00
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait()
        .await
        .unwrap();
    assert_eq!(canister_id, effective_canister_id.into());

    // install II canister WASM
    let ii_path = std::env::var_os("II_WASM").expect("Missing II_WASM (path to II wasm) in env.");
    let ii_wasm = std::fs::read(ii_path).expect("Could not read II wasm file.");
    ic00.install_code(&canister_id, &ii_wasm)
        .with_raw_arg(Encode!(&()).unwrap())
        .call_and_wait()
        .await
        .unwrap();

    // perform frontend asset request for the title page at http://127.0.0.1:<port>/?canisterId=<canister-id>
    if !https {
        assert_eq!(proto, "http");
        let canister_url = format!(
            "{}://{}:{}/?canisterId={}",
            "http", "127.0.0.1", port, canister_id
        );
        let res = client.get(canister_url).send().await.unwrap();
        let page = String::from_utf8(res.bytes().await.unwrap().to_vec()).unwrap();
        println!("page: {}", page);
        assert!(page.contains("<title>Internet Identity</title>"));
    }

    // perform frontend asset request for the title page at http(s)://localhost:<port>/?canisterId=<canister-id>
    let canister_url = format!(
        "{}://{}:{}/?canisterId={}",
        proto, localhost, port, canister_id
    );
    let res = client.get(canister_url).send().await.unwrap();
    let page = String::from_utf8(res.bytes().await.unwrap().to_vec()).unwrap();
    assert!(page.contains("<title>Internet Identity</title>"));

    // perform frontend asset request for the title page at http(s)://<canister-id>.example.com:<port>
    let canister_url = format!("{}://{}.{}:{}", proto, canister_id, alt_domain, port);
    let res = client.get(canister_url.clone()).send().await.unwrap();
    let page = String::from_utf8(res.bytes().await.unwrap().to_vec()).unwrap();
    assert!(page.contains("<title>Internet Identity</title>"));

    // stop HTTP gateway and disable auto progress
    pic.stop_live().await;

    // HTTP gateway should eventually stop and requests to it fail
    loop {
        if client.get(canister_url.clone()).send().await.is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[tokio::test]
async fn test_http_gateway() {
    let server_url = start_server();
    test_gateway(server_url, false).await;
}

#[tokio::test]
async fn test_https_gateway() {
    let server_url = start_server();
    test_gateway(server_url, true).await;
}

#[test]
fn test_specified_id() {
    use ic_utils::interfaces::ManagementCanister;

    // Create live PocketIc instance.
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let endpoint = pic.make_live(None);

    // We define a "specified" canister ID that exists on the IC mainnet,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    let specified_id = Principal::from_text("rimrc-piaaa-aaaao-aaljq-cai").unwrap();
    assert!(pic.get_subnet(specified_id).is_none());

    // We create a canister with that specified canister ID: this should succeed
    // and a new subnet should be created.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let canister_id = rt.block_on(async {
        let agent = ic_agent::Agent::builder()
            .with_url(endpoint.clone())
            .build()
            .unwrap();
        agent.fetch_root_key().await.unwrap();

        let ic00 = ManagementCanister::create(&agent);

        let (canister_id,) = ic00
            .create_canister()
            .as_provisional_create_with_specified_id(specified_id)
            .call_and_wait()
            .await
            .unwrap();

        canister_id
    });
    assert_eq!(canister_id, specified_id);
}

#[test]
fn test_dashboard() {
    let (server_url, _) = start_server_helper(None, false, false);
    let subnet_config_set = SubnetConfigSet {
        nns: true,
        application: 1,
        ..Default::default()
    };
    let mut pic = PocketIc::from_config_and_server_url(subnet_config_set, server_url.clone());

    // retrieve the NNS and application subnets
    let topology = pic.topology();
    let nns_subnet = topology.get_nns().unwrap();
    let app_subnet = topology.get_app_subnets()[0];

    let canister_1 = pic.create_canister_on_subnet(None, None, nns_subnet);
    assert_eq!(pic.get_subnet(canister_1).unwrap(), nns_subnet);
    let canister_2 = pic.create_canister_on_subnet(None, None, app_subnet);
    assert_eq!(pic.get_subnet(canister_2).unwrap(), app_subnet);

    let gateway = pic.make_live(None);

    let client = Client::new();
    let instance_dashboard_url =
        format!("{}instances/{}/_/dashboard", server_url, pic.instance_id());
    let gateway_dashboard_url = gateway.join("_/dashboard").unwrap().to_string();
    for dashboard_url in [instance_dashboard_url, gateway_dashboard_url] {
        let dashboard = client.get(dashboard_url).send().unwrap();
        let page = String::from_utf8(dashboard.bytes().unwrap().to_vec()).unwrap();
        assert!(page.contains(&canister_1.to_string()));
        assert!(page.contains(&canister_2.to_string()));
        assert!(page.contains(&nns_subnet.to_string()));
        assert!(page.contains(&app_subnet.to_string()));
    }
}

#[test]
fn pocket_ic_server_binary_name() {
    let bin_path = std::env::var_os("POCKET_IC_BIN").expect("Missing PocketIC binary");
    let new_bin_path = format!("{}_", bin_path.to_str().unwrap());
    Command::new("cp")
        .arg(bin_path.clone())
        .arg(new_bin_path.clone())
        .output()
        .unwrap();
    let out = Command::new(PathBuf::from(new_bin_path))
        .output()
        .expect("Failed to start PocketIC binary");
    let out_str = String::from_utf8(out.stderr).unwrap();
    assert!(out_str.contains(
        "The PocketIc server binary name must be \"pocket-ic\" or \"pocket-ic-server\" (without quotes)."
    ));
}

const CANISTER_LOGS_WAT: &str = r#"
    (module
        (import "ic0" "debug_print"
            (func $debug_print (param i32 i32)))
        (func $init
            (call $debug_print (i32.const 0) (i32.const 14))
        )
        (memory $memory 1)
        (export "canister_init" (func $init))
        (data (i32.const 0) "Logging works!")
    )
"#;

#[test]
fn canister_and_replica_logs() {
    const INIT_CYCLES: u128 = 2_000_000_000_000;
    let (server_url, mut out) = start_server_helper(None, true, true);
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_server_url(server_url)
        .with_log_level(Level::Info)
        .build();

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    let canister_logs_wasm = wat::parse_str(CANISTER_LOGS_WAT).unwrap();
    pic.install_canister(canister_id, canister_logs_wasm, vec![], None);

    drop(pic);

    // kill the server to avoid blocking until TTL is hit
    out.kill().unwrap();

    let mut stdout = String::new();
    out.stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert!(stdout.contains("Finished executing install_code message on canister CanisterId(lxzze-o7777-77777-aaaaa-cai)"));

    let mut stderr = String::new();
    out.stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.contains("Logging works!"));
}

#[test]
fn canister_and_no_replica_logs() {
    const INIT_CYCLES: u128 = 2_000_000_000_000;
    let (server_url, mut out) = start_server_helper(None, true, true);
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_server_url(server_url)
        .with_log_level(Level::Error)
        .build();

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    let canister_logs_wasm = wat::parse_str(CANISTER_LOGS_WAT).unwrap();
    pic.install_canister(canister_id, canister_logs_wasm, vec![], None);

    drop(pic);

    // kill the server to avoid blocking until TTL is hit
    out.kill().unwrap();

    let mut stdout = String::new();
    out.stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert!(!stdout.contains("Finished executing install_code message on canister CanisterId(lxzze-o7777-77777-aaaaa-cai)"));

    let mut stderr = String::new();
    out.stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.contains("Logging works!"));
}

const COUNTER_WAT: &str = r#"
;; Counter with global variable ;;
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (import "ic0" "msg_reply_data_append"
    (func $msg_reply_data_append (param i32 i32)))

  (func $read
    (i32.store
      (i32.const 0)
      (global.get 0)
    )
    (call $msg_reply_data_append
      (i32.const 0)
      (i32.const 4))
    (call $msg_reply))

  (func $write
    (global.set 0
      (i32.add
        (global.get 0)
        (i32.const 1)
      )
    )
    (call $read)
  )

  (memory $memory 1)
  (export "memory" (memory $memory))
  (global (export "counter_global") (mut i32) (i32.const 0))
  (export "canister_query read" (func $read))
  (export "canister_query inc_read" (func $write))
  (export "canister_update write" (func $write))
)
    "#;

fn check_counter(pic: &PocketIc, canister_id: Principal, expected_ctr: u32) {
    let res = pic
        .query_call(canister_id, Principal::anonymous(), "read", vec![])
        .unwrap();
    match res {
        WasmResult::Reply(data) => {
            assert_eq!(u32::from_le_bytes(data.try_into().unwrap()), expected_ctr);
        }
        _ => panic!("Unexpected update call response"),
    };
}

/// Tests that the PocketIC topology and canister states
/// can be successfully restored from a `state_dir`
/// if a PocketIC instance is created with that `state_dir`,
/// using `with_state_dir` on `PocketIcBuilder`.
/// Furthermore, tests that the NNS subnet and its canister states
/// can be successfully restored from the NNS subnet state,
/// using `with_nns_state` on `PocketIcBuilder`.
#[test]
fn canister_state_dir() {
    const INIT_CYCLES: u128 = 2_000_000_000_000;

    // Create a temporary state directory persisted throughout the test.
    let state_dir = TempDir::new().unwrap();
    let state_dir_path_buf = state_dir.path().to_path_buf();

    // Create a PocketIC instance with NNS and app subnets.
    let pic = PocketIcBuilder::new()
        .with_state_dir(state_dir_path_buf.clone())
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // Check the registry version.
    // The registry version should be 2 as we have two subnets on the PocketIC instance
    // and every subnet creation bumps the registry version.
    let registry_proto_path = state_dir_path_buf.join("registry.proto");
    let registry_data_provider = ProtoRegistryDataProvider::load_from_file(registry_proto_path);
    assert_eq!(registry_data_provider.latest_version(), 2.into());

    // Retrieve the NNS and app subnets from the topology.
    let topology = pic.topology();
    let nns_subnet = topology.get_nns().unwrap();
    let app_subnet = topology.get_app_subnets()[0];

    // We create a counter canister on the NNS subnet.
    let nns_canister_id = pic.create_canister_on_subnet(None, None, nns_subnet);
    pic.add_cycles(nns_canister_id, INIT_CYCLES);
    let counter_wasm = wat::parse_str(COUNTER_WAT).unwrap();
    pic.install_canister(nns_canister_id, counter_wasm, vec![], None);

    // Bump the counter twice and check the counter value.
    pic.update_call(nns_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();
    pic.update_call(nns_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();
    check_counter(&pic, nns_canister_id, 2);

    // We create a counter canister on the application subnet.
    let app_canister_id = pic.create_canister_on_subnet(None, None, app_subnet);
    pic.add_cycles(app_canister_id, INIT_CYCLES);
    let counter_wasm = wat::parse_str(COUNTER_WAT).unwrap();
    pic.install_canister(app_canister_id, counter_wasm, vec![], None);

    // Bump the counter once and check the counter value.
    pic.update_call(app_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();
    check_counter(&pic, app_canister_id, 1);

    // We create a counter canister with a "specified" canister ID that exists on the IC mainnet,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    let specified_id = Principal::from_text("rimrc-piaaa-aaaao-aaljq-cai").unwrap();
    assert!(pic.get_subnet(specified_id).is_none());
    let spec_canister_id = pic
        .create_canister_with_id(None, None, specified_id)
        .unwrap();
    assert_eq!(spec_canister_id, specified_id);
    pic.add_cycles(spec_canister_id, INIT_CYCLES);
    let counter_wasm = wat::parse_str(COUNTER_WAT).unwrap();
    pic.install_canister(spec_canister_id, counter_wasm, vec![], None);

    // Bump the counter three times and check the counter value.
    pic.update_call(spec_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();
    pic.update_call(spec_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();
    pic.update_call(spec_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();
    check_counter(&pic, spec_canister_id, 3);

    // Delete the PocketIC instance.
    drop(pic);

    // Start a new PocketIC server.
    let (new_server_url, _) = start_server_helper(None, false, false);

    // Create a PocketIC instance mounting the state created so far.
    let pic = PocketIcBuilder::new()
        .with_server_url(new_server_url)
        .with_state_dir(state_dir_path_buf.clone())
        .build();

    // Check that the topology has been properly restored.
    let topology = pic.topology();
    assert_eq!(topology.get_nns().unwrap(), nns_subnet);
    assert_eq!(topology.get_app_subnets()[0], app_subnet);
    // We created one app subnet and another one was created dynamically
    // to host the canister with the "specified" canister ID.
    assert_eq!(topology.get_app_subnets().len(), 2);

    // Check that the canister states have been properly restored.
    check_counter(&pic, nns_canister_id, 2);
    check_counter(&pic, app_canister_id, 1);
    check_counter(&pic, spec_canister_id, 3);

    // Bump the counter on the NNS subnet.
    pic.update_call(nns_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();

    // Delete the PocketIC instance.
    drop(pic);

    // Start a new PocketIC server.
    let (newest_server_url, _) = start_server_helper(None, false, false);

    // Create a PocketIC instance mounting the NNS state created so far.
    let nns_subnet_seed = topology.0.get(&nns_subnet).unwrap().subnet_seed;
    let nns_state_dir = state_dir.path().join(hex::encode(nns_subnet_seed));
    let pic = PocketIcBuilder::new()
        .with_server_url(newest_server_url)
        .with_nns_state(nns_subnet, nns_state_dir)
        .build();

    // Check that the topology has been properly restored.
    let topology = pic.topology();
    assert_eq!(topology.get_nns().unwrap(), nns_subnet);
    // We didn't specify to restore any app subnets.
    assert!(topology.get_app_subnets().is_empty());

    // Check that the canister states have been properly restored.
    check_counter(&pic, nns_canister_id, 3);

    // Bump the counter on the NNS subnet.
    pic.update_call(nns_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();

    // Check the registry version.
    // The registry version should be 3 as we have three subnets on the PocketIC instance now
    // and every subnet creation bumps the registry version.
    let registry_proto_path = state_dir_path_buf.join("registry.proto");
    let registry_data_provider = ProtoRegistryDataProvider::load_from_file(registry_proto_path);
    assert_eq!(registry_data_provider.latest_version(), 3.into());
}

/// Test that PocketIC can handle synchronous update calls, i.e. `/api/v3/.../call`.
#[test]
fn test_specified_id_call_v3() {
    // Create live PocketIc instance.
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let endpoint = pic.make_live(None);

    // retrieve the first canister ID on the application subnet
    // which will be the effective canister ID for canister creation
    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];
    let effective_canister_id =
        raw_canister_id_range_into(&topology.0.get(&app_subnet).unwrap().canister_ranges[0]).start;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let transport = ReqwestTransport::create(endpoint.clone())
            .unwrap()
            .with_use_call_v3_endpoint();

        let agent = ic_agent::Agent::builder()
            .with_transport(transport)
            .build()
            .unwrap();
        agent.fetch_root_key().await.unwrap();

        let arg = ProvisionalCreateCanisterWithCyclesArgs {
            amount: None,
            settings: None,
            specified_id: None,
            sender_canister_version: None,
        };
        let bytes = candid::Encode!(&arg).unwrap();

        // Submit a call to the `/api/v3/.../call` endpoint.
        // Note that this might be flaky if it takes more than 10 seconds to process the update call
        // (then `CallResponse::Poll` would be returned and this test would panic).
        agent
            .update(
                &Principal::management_canister(),
                "provisional_create_canister_with_cycles",
            )
            .with_arg(bytes)
            .with_effective_canister_id(effective_canister_id.into())
            .call()
            .await
            .map(|response| match response {
                CallResponse::Poll(_) => panic!("Expected a reply"),
                CallResponse::Response(..) => {}
            })
            .unwrap();
    })
}

/// Test that query stats are available via the management canister.
#[test]
fn test_query_stats() {
    const INIT_CYCLES: u128 = 2_000_000_000_000;

    // Create PocketIC instance with a single app subnet.
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    // We create a counter canister on the app subnet.
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    let counter_wasm = wat::parse_str(COUNTER_WAT).unwrap();
    pic.install_canister(canister_id, counter_wasm, vec![], None);

    // The query stats are still at zero.
    let query_stats = pic.canister_status(canister_id, None).unwrap().query_stats;
    let zero: candid::Nat = 0_u64.into();
    assert_eq!(query_stats.num_calls_total, zero);
    assert_eq!(query_stats.num_instructions_total, zero);
    assert_eq!(query_stats.request_payload_bytes_total, zero);
    assert_eq!(query_stats.response_payload_bytes_total, zero);

    // Execute 13 query calls (one per each app subnet node) on the counter canister in each of 4 query stats epochs.
    // Every single query call has different arguments so that query calls are not cached.
    let mut n: u64 = 0;
    for _ in 0..4 {
        for _ in 0..13 {
            pic.query_call(
                canister_id,
                Principal::anonymous(),
                "read",
                n.to_le_bytes().to_vec(),
            )
            .unwrap();
            n += 1;
        }
        // Execute one epoch.
        for _ in 0..60 {
            pic.tick();
        }
    }

    // Now the number of calls should be set to 26 (13 calls per epoch from 2 epochs) due to a delay in query stats aggregation.
    let query_stats = pic.canister_status(canister_id, None).unwrap().query_stats;
    assert_eq!(query_stats.num_calls_total, candid::Nat::from(26_u64));
    assert_ne!(query_stats.num_instructions_total, candid::Nat::from(0_u64));
    assert_eq!(
        query_stats.request_payload_bytes_total,
        candid::Nat::from(208_u64)
    ); // we sent 8 bytes per call
    assert_eq!(
        query_stats.response_payload_bytes_total,
        candid::Nat::from(104_u64)
    ); // the counter canister responds with 4 bytes per call
}

/// Test that query stats are available via the management canister in the live mode of PocketIC.
#[test]
fn test_query_stats_live() {
    const INIT_CYCLES: u128 = 2_000_000_000_000;

    // Create PocketIC instance with one NNS subnet and one app subnet.
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // Retrieve the app subnet from the topology.
    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];

    // We create a counter canister on the app subnet.
    let canister_id = pic.create_canister_on_subnet(None, None, app_subnet);
    pic.add_cycles(canister_id, INIT_CYCLES);
    let counter_wasm = wat::parse_str(COUNTER_WAT).unwrap();
    pic.install_canister(canister_id, counter_wasm, vec![], None);

    // Query stats should be collected in the live mode.
    let endpoint = pic.make_live(None);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let agent = ic_agent::Agent::builder()
            .with_url(endpoint.clone())
            .build()
            .unwrap();
        agent.fetch_root_key().await.unwrap();

        let ic00 = ManagementCanister::create(&agent);

        let query_stats = ic00
            .canister_status(&canister_id)
            .await
            .unwrap()
            .0
            .query_stats;
        assert_eq!(query_stats.num_calls_total, candid::Nat::from(0_u64));

        let mut n: u64 = 0;
        loop {
            // Make one query call per app subnet node.
            for _ in 0..13 {
                agent
                    .query(&canister_id, "read")
                    .with_arg(n.to_le_bytes().to_vec())
                    .call()
                    .await
                    .unwrap();
                n += 1;
            }

            let current_query_stats = ic00
                .canister_status(&canister_id)
                .await
                .unwrap()
                .0
                .query_stats;
            if query_stats.num_calls_total != current_query_stats.num_calls_total {
                break;
            }
        }
    })
}

/// Tests subnet read state requests.
#[test]
fn test_subnet_read_state() {
    const INIT_CYCLES: u128 = 2_000_000_000_000;

    // Create PocketIC instance with one NNS subnet and one app subnet.
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // Retrieve the app subnet from the topology.
    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];

    // We create a counter canister on the app subnet.
    let canister_id = pic.create_canister_on_subnet(None, None, app_subnet);
    pic.add_cycles(canister_id, INIT_CYCLES);
    let counter_wasm = wat::parse_str(COUNTER_WAT).unwrap();
    pic.install_canister(canister_id, counter_wasm, vec![], None);

    let endpoint = pic.make_live(None);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let agent = ic_agent::Agent::builder()
            .with_url(endpoint.clone())
            .build()
            .unwrap();
        agent.fetch_root_key().await.unwrap();

        let metrics = agent.read_state_subnet_metrics(app_subnet).await.unwrap();
        assert_eq!(metrics.num_canisters, 1);
    })
}

/// Tests that HTTP gateway can handle requests with IP address hosts.
#[test]
fn test_gateway_ip_addr_host() {
    // Create PocketIC instance with one NNS subnet and one app subnet.
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // Retrieve the app subnet from the topology.
    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];

    // We create a canister on the app subnet.
    pic.create_canister_on_subnet(None, None, app_subnet);

    let mut endpoint = pic.make_live(None);
    endpoint
        .set_ip_host(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        .unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let agent = ic_agent::Agent::builder()
            .with_url(endpoint.clone())
            .build()
            .unwrap();
        agent.fetch_root_key().await.unwrap();

        let metrics = agent.read_state_subnet_metrics(app_subnet).await.unwrap();
        assert_eq!(metrics.num_canisters, 1);
    })
}

#[test]
fn test_unresponsive_gateway_backend() {
    let client = Client::new();

    // Create PocketIC instance with one NNS subnet and one app subnet.
    let (backend_server_url, mut backend_process) = start_server_helper(None, false, false);
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_server_url(backend_server_url.clone())
        .build();

    // Create HTTP gateway on a different gateway server.
    let (gateway_server_url, _) = start_server_helper(None, false, false);
    let create_gateway_endpoint = gateway_server_url.join("http_gateway").unwrap();
    let backend_instance_url = backend_server_url
        .join(&format!("instances/{}/", pic.instance_id()))
        .unwrap();
    let http_gateway_config = HttpGatewayConfig {
        ip_addr: None,
        port: None,
        forward_to: HttpGatewayBackend::Replica(backend_instance_url.to_string()),
        domains: None,
        https_config: None,
    };
    let res = client
        .post(create_gateway_endpoint)
        .json(&http_gateway_config)
        .send()
        .unwrap()
        .json::<CreateHttpGatewayResponse>()
        .unwrap();
    let endpoint = match res {
        CreateHttpGatewayResponse::Created(info) => {
            let port = info.port;
            Url::parse(&format!("http://localhost:{}/", port)).unwrap()
        }
        CreateHttpGatewayResponse::Error { message } => {
            panic!("Failed to crate http gateway: {}", message)
        }
    };

    // Query the status endpoint via HTTP gateway.
    let resp = client
        .get(endpoint.join("api/v2/status").unwrap())
        .send()
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Kill the backend server, but keep the HTTP gateway running.
    drop(pic);
    backend_process.kill().unwrap();

    // Query the status endpoint via HTTP gateway again.
    let resp = client
        .get(endpoint.join("api/v2/status").unwrap())
        .send()
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert!(String::from_utf8(resp.bytes().unwrap().as_ref().to_vec())
        .unwrap()
        .contains("connection_failure: client error"));
}

#[test]
fn test_invalid_gateway_backend() {
    // Create HTTP gateway with an invalid backend URL
    let (gateway_server_url, _) = start_server_helper(None, false, false);
    let create_gateway_endpoint = gateway_server_url.join("http_gateway").unwrap();
    let backend_url = "http://240.0.0.0";
    let http_gateway_config = HttpGatewayConfig {
        ip_addr: None,
        port: None,
        forward_to: HttpGatewayBackend::Replica(backend_url.to_string()),
        domains: None,
        https_config: None,
    };
    let client = Client::new();
    let res = client
        .post(create_gateway_endpoint)
        .json(&http_gateway_config)
        .send()
        .unwrap()
        .json::<CreateHttpGatewayResponse>()
        .unwrap();
    match res {
        CreateHttpGatewayResponse::Created(_info) => {
            panic!("Suceeded to create http gateway!")
        }
        CreateHttpGatewayResponse::Error { message } => {
            assert!(message.contains("An error happened during communication with the replica: error sending request for url"));
        }
    };
}

fn record_to_mutation(r: RegistryVersionedRecord<Vec<u8>>) -> RegistryMutation {
    let mut m = RegistryMutation::default();

    let t = if r.value.is_none() {
        Type::Delete
    } else {
        Type::Insert
    };
    m.set_mutation_type(t);
    m.key = r.key.as_bytes().to_vec();
    m.value = r.value.unwrap_or_default();

    m
}

#[test]
fn registry_canister() {
    // Create a temporary state directory persisted throughout the test.
    let state_dir = TempDir::new().unwrap();
    let state_dir_path_buf = state_dir.path().to_path_buf();

    // Create a PocketIC instance with NNS, II and two app subnets.
    let pic = PocketIcBuilder::new()
        .with_state_dir(state_dir_path_buf.clone())
        .with_nns_subnet()
        .with_ii_subnet()
        .with_application_subnet()
        .with_application_subnet()
        .build();

    // Encode the local registry into a registry canister initial payload.
    let registry_proto_path = state_dir_path_buf.join("registry.proto");
    let registry_data_provider = ProtoRegistryDataProvider::load_from_file(registry_proto_path);
    let updates = registry_data_provider
        .get_updates_since(ZERO_REGISTRY_VERSION)
        .unwrap();
    let mutations = updates
        .into_iter()
        .map(record_to_mutation)
        .collect::<Vec<RegistryMutation>>();
    let mutate_request = RegistryAtomicMutateRequest {
        mutations,
        ..Default::default()
    };
    let registry_init_payload = RegistryCanisterInitPayload {
        mutations: vec![mutate_request],
    };

    // Create the registry canister.
    let registry_canister_id = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
    let actual_registry_canister_id = pic
        .create_canister_with_id(None, None, registry_canister_id)
        .unwrap();
    assert_eq!(registry_canister_id, actual_registry_canister_id);

    // Install the registry canister.
    let registry_path = std::env::var_os("REGISTRY_WASM")
        .expect("Missing REGISTRY_WASM (path to REGISTRY wasm) in env.");
    let registry_canister_wasm =
        std::fs::read(registry_path).expect("Could not read REGISTRY wasm file.");
    pic.install_canister(
        registry_canister_id,
        registry_canister_wasm,
        Encode!(&registry_init_payload).unwrap(),
        None,
    );
}

#[test]
fn provisional_create_canister_with_cycles() {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    let arg = ProvisionalCreateCanisterWithCyclesArgument::default();
    let res: (CanisterIdRecord,) = update_candid(
        &pic,
        Principal::management_canister(),
        "provisional_create_canister_with_cycles",
        (arg,),
    )
    .unwrap();
    let canister_id = res.0.canister_id;

    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];
    assert_eq!(pic.get_subnet(canister_id).unwrap(), app_subnet);
}
