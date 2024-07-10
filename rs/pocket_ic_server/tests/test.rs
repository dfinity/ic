mod common;

use crate::common::raw_canister_id_range_into;
use candid::{Encode, Principal};
use ic_agent::agent::http_transport::ReqwestTransport;
use ic_utils::interfaces::ManagementCanister;
use pocket_ic::common::rest::{HttpsConfig, InstanceConfig, SubnetConfigSet};
use pocket_ic::{PocketIc, PocketIcBuilder, WasmResult};
use rcgen::{CertificateParams, KeyPair};
use reqwest::blocking::Client;
use reqwest::Client as NonblockingClient;
use reqwest::{StatusCode, Url};
use std::io::Read;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};

pub const LOCALHOST: &str = "127.0.0.1";

fn start_server_helper(
    parent_pid: Option<u32>,
    ttl: Option<u64>,
    capture_stderr: bool,
) -> (Url, Child) {
    let bin_path = std::env::var_os("POCKET_IC_BIN").expect("Missing PocketIC binary");
    let port_file_path = if let Some(parent_pid) = parent_pid {
        std::env::temp_dir().join(format!("pocket_ic_{}.port", parent_pid))
    } else {
        NamedTempFile::new().unwrap().into_temp_path().to_path_buf()
    };
    let ready_file_path = if let Some(parent_pid) = parent_pid {
        std::env::temp_dir().join(format!("pocket_ic_{}.ready", parent_pid))
    } else {
        NamedTempFile::new().unwrap().into_temp_path().to_path_buf()
    };
    let mut cmd = Command::new(PathBuf::from(bin_path));
    if let Some(parent_pid) = parent_pid {
        cmd.arg("--pid").arg(parent_pid.to_string());
    } else {
        cmd.arg("--port-file").arg(port_file_path.clone());
        cmd.arg("--ready-file").arg(ready_file_path.clone());
    }
    if let Some(ttl) = ttl {
        cmd.arg("--ttl").arg(ttl.to_string());
    }
    if capture_stderr {
        cmd.stderr(std::process::Stdio::piped());
    }
    let out = cmd.spawn().expect("Failed to start PocketIC binary");
    let start = Instant::now();
    let url = loop {
        match ready_file_path.try_exists() {
            Ok(true) => {
                let port_string = std::fs::read_to_string(port_file_path)
                    .expect("Failed to read port from port file");
                let port: u16 = port_string.parse().expect("Failed to parse port to number");
                break Url::parse(&format!("http://{}:{}/", LOCALHOST, port)).unwrap();
            }
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
        if start.elapsed() > Duration::from_secs(5) {
            panic!("Failed to start PocketIC service in time");
        }
    };
    (url, out)
}

pub fn start_server() -> Url {
    let parent_pid = std::os::unix::process::parent_id();
    start_server_helper(Some(parent_pid), None, false).0
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
    let bin_path = std::env::var_os("POCKET_IC_BIN").expect("Missing PocketIC binary");
    let port_file_path = std::env::temp_dir().join("pocket_ic.port");
    Command::new(PathBuf::from(bin_path))
        .arg("--port-file")
        .arg(
            port_file_path
                .clone()
                .into_os_string()
                .into_string()
                .unwrap(),
        )
        .spawn()
        .expect("Failed to start PocketIC binary");
    let start = Instant::now();
    loop {
        if let Ok(port_string) = std::fs::read_to_string(port_file_path.clone()) {
            if !port_string.is_empty() {
                port_string
                    .parse::<u16>()
                    .expect("Failed to parse port to number");
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
        if start.elapsed() > Duration::from_secs(5) {
            panic!("Failed to start PocketIC service in time");
        }
    }
}

async fn test_gateway(https: bool) {
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
    let https_config = if https {
        Some(HttpsConfig {
            cert_path: cert_path.into_os_string().into_string().unwrap(),
            key_path: key_path.into_os_string().into_string().unwrap(),
        })
    } else {
        None
    };
    let port = pic
        .make_live_with_params(
            None,
            Some(vec![localhost.to_string(), alt_domain.to_string()]),
            https_config,
        )
        .await
        .port_or_known_default()
        .unwrap();

    // create a non-blocking reqwest client resolving localhost/example.com and <canister-id>.localhost/example.com to [::1]
    let mut builder = NonblockingClient::builder()
        .resolve(
            localhost,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), port),
        )
        .resolve(
            sub_localhost,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), port),
        )
        .resolve(
            alt_domain,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), port),
        )
        .resolve(
            sub_alt_domain,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), port),
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
    test_gateway(false).await;
}

#[tokio::test]
async fn test_https_gateway() {
    test_gateway(true).await;
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
    let (server_url, _) = start_server_helper(None, Some(5), true);
    let subnet_config_set = SubnetConfigSet {
        nns: true,
        application: 1,
        ..Default::default()
    };
    let pic = PocketIc::from_config_and_server_url(subnet_config_set, server_url.clone());

    // retrieve the NNS and application subnets
    let topology = pic.topology();
    let nns_subnet = topology.get_nns().unwrap();
    let app_subnet = topology.get_app_subnets()[0];

    let canister_1 = pic.create_canister_on_subnet(None, None, nns_subnet);
    assert_eq!(pic.get_subnet(canister_1).unwrap(), nns_subnet);
    let canister_2 = pic.create_canister_on_subnet(None, None, app_subnet);
    assert_eq!(pic.get_subnet(canister_2).unwrap(), app_subnet);

    let client = Client::new();
    let dashboard_url = format!("{}instances/{}/_/dashboard", server_url, pic.instance_id());
    let dashboard = client.get(dashboard_url).send().unwrap();
    let page = String::from_utf8(dashboard.bytes().unwrap().to_vec()).unwrap();
    assert!(page.contains(&canister_1.to_string()));
    assert!(page.contains(&canister_2.to_string()));
    assert!(page.contains(&nns_subnet.to_string()));
    assert!(page.contains(&app_subnet.to_string()));
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
fn canister_logs() {
    const INIT_CYCLES: u128 = 2_000_000_000_000;
    let (server_url, mut out) = start_server_helper(None, Some(5), true);
    let subnet_config_set = SubnetConfigSet {
        application: 1,
        ..Default::default()
    };
    let pic = PocketIc::from_config_and_server_url(subnet_config_set, server_url);

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, INIT_CYCLES);
    let canister_logs_wasm = wat::parse_str(CANISTER_LOGS_WAT).unwrap();
    pic.install_canister(canister_id, canister_logs_wasm, vec![], None);

    drop(pic);
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

    // Create a PocketIC instance with NNS and app subets.
    let pic = PocketIcBuilder::new()
        .with_state_dir(state_dir_path_buf.clone())
        .with_nns_subnet()
        .with_application_subnet()
        .build();

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
    let (new_server_url, _) = start_server_helper(None, Some(5), false);

    // Create a PocketIC instance mounting the state created so far.
    let pic = PocketIcBuilder::new()
        .with_server_url(new_server_url)
        .with_state_dir(state_dir_path_buf)
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
    let (newest_server_url, _) = start_server_helper(None, Some(5), false);

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
}
