mod common;

use crate::common::raw_canister_id_range_into;
use candid::Encode;
use pocket_ic::common::rest::SubnetConfigSet;
use pocket_ic::{PocketIc, PocketIcBuilder};
use reqwest::blocking::Client;
use reqwest::{StatusCode, Url};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

pub const LOCALHOST: &str = "127.0.0.1";

pub fn start_server_helper(
    parent_pid: u32,
    ttl: Option<u64>,
    capture_stderr: bool,
) -> (Url, Child) {
    let bin_path = std::env::var_os("POCKET_IC_BIN").expect("Missing PocketIC binary");
    let mut cmd = Command::new(PathBuf::from(bin_path));
    cmd.arg("--pid").arg(parent_pid.to_string());
    if let Some(ttl) = ttl {
        cmd.arg("--ttl").arg(ttl.to_string());
    }
    if capture_stderr {
        cmd.stderr(std::process::Stdio::piped());
    }
    let out = cmd.spawn().expect("Failed to start PocketIC binary");
    let port_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.port", parent_pid));
    let ready_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.ready", parent_pid));
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
    start_server_helper(parent_pid, None, false).0
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

    // create live PocketIc instance
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let endpoint = pic.make_live(None);
    let app_subnet = pic.topology().get_app_subnets()[0];
    let effective_canister_id =
        raw_canister_id_range_into(&pic.topology().0.get(&app_subnet).unwrap().canister_ranges[0])
            .start;

    // deploy II canister to PocketIc instance proxying through HTTP gateway
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let ii_canister_id = rt.block_on(async {
        let agent = ic_agent::Agent::builder()
            .with_url(endpoint.clone())
            .build()
            .unwrap();
        agent.fetch_root_key().await.unwrap();

        let ic00 = ManagementCanister::create(&agent);

        let (canister_id,) = ic00
            .create_canister()
            .as_provisional_create_with_amount(None)
            .with_effective_canister_id(effective_canister_id)
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
    let ii_url = endpoint
        .join(&format!("?canisterId={}", ii_canister_id))
        .unwrap();
    let client = Client::new();
    let res = client.get(ii_url.clone()).send().unwrap();
    let page = String::from_utf8(res.bytes().unwrap().to_vec()).unwrap();
    assert!(page.contains("<title>Internet Identity</title>"));

    // stop HTTP gateway and make IC instance deterministic
    pic.make_deterministic();

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
