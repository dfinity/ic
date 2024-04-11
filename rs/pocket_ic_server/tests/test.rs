mod common;

use crate::common::{
    create_live_instance, raw_canister_id_range_into, start_server, start_server_helper,
};
use candid::Encode;
use pocket_ic::common::rest::{
    CreateHttpGatewayResponse, DtsFlag, HttpGatewayBackend, HttpGatewayConfig, SubnetConfigSet,
};
use pocket_ic::PocketIc;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn test_status() {
    let url = start_server();
    let client = Client::new();

    let response = client.get(url.join("status/").unwrap()).send().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn test_creation_of_instance_extended() {
    use pocket_ic::common::rest::ExtendedSubnetConfigSet;
    let url = start_server();
    let client = Client::new();
    let response = client
        .post(url.join("instances").unwrap())
        .json(&Into::<ExtendedSubnetConfigSet>::into(SubnetConfigSet {
            application: 1,
            ..Default::default()
        }))
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

#[test]
fn test_http_gateway() {
    use ic_utils::interfaces::ManagementCanister;

    // create PocketIc instance in auto progress mode
    let url = start_server();
    let client = Client::new();
    let (instance_id, _nns_subnet_id, _nns_config, _app_subnet_id, app_config) =
        create_live_instance(&url, &client, DtsFlag::Enabled);

    // start HTTP gateway
    let http_gateway_url = url.join("http_gateway").unwrap();
    let body = HttpGatewayConfig {
        listen_at: None,
        forward_to: HttpGatewayBackend::PocketIcInstance(instance_id),
    };
    let (http_gateway_id, http_gateway_port) = match client
        .post(http_gateway_url)
        .json(&body)
        .send()
        .unwrap()
        .json::<CreateHttpGatewayResponse>()
        .expect("Could not parse response for create HTTP gateway request")
    {
        CreateHttpGatewayResponse::Created { instance_id, port } => (instance_id, port),
        CreateHttpGatewayResponse::Error { message } => panic!("{}", message),
    };

    // deploy II canister to PocketIc instance proxying through HTTP gateway
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let ii_canister_id = rt.block_on(async {
        let agent_endpoint = format!("http://localhost:{}", http_gateway_port);
        let agent = ic_agent::Agent::builder()
            .with_url(agent_endpoint)
            .build()
            .unwrap();
        agent.fetch_root_key().await.unwrap();

        let ic00 = ManagementCanister::create(&agent);

        let app_canister_id = raw_canister_id_range_into(&app_config.canister_ranges[0]).start;
        let (canister_id,) = ic00
            .create_canister()
            .as_provisional_create_with_amount(None)
            .with_effective_canister_id(app_canister_id)
            .call_and_wait()
            .await
            .unwrap();

        let ii_path =
            std::env::var_os("II_WASM").expect("Missing II_WASM (path to II wasm) in env.");
        let ii_wasm = std::fs::read(ii_path).expect("Could not read II wasm file.");
        ic00.install_code(&canister_id, &ii_wasm)
            .with_raw_arg(Encode!(&()).unwrap())
            .call_and_wait()
            .await
            .unwrap();

        canister_id
    });

    // perform frontend asset request for the title page
    let ii_url = format!(
        "http://localhost:{}/?canisterId={}",
        http_gateway_port, ii_canister_id
    );
    let res = client.get(ii_url.clone()).send().unwrap();
    let page = String::from_utf8(res.bytes().unwrap().to_vec()).unwrap();
    assert!(page.contains("<title>Internet Identity</title>"));

    // stop HTTP gateway
    let stop_http_gateway_url = url
        .join(&format!("http_gateway/{}/stop", http_gateway_id))
        .unwrap();
    client
        .post(stop_http_gateway_url)
        .send()
        .unwrap()
        .json::<()>()
        .expect("Could not parse response for stop HTTP gateway request");

    // HTTP gateway requests should eventually stop and requests to it fail
    loop {
        if client.get(ii_url.clone()).send().is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
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
        "The PocketIc server binary name must be \"pocket-ic-server\" (without quotes)."
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
    let (server_url, mut out) = start_server_helper(0, Some(5), true);
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
