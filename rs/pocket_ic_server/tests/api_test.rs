use candid::{decode_args, encode_args, Principal};
use ic_cdk::api::management_canister::main::{CanisterIdRecord, CreateCanisterArgument};
use pocket_ic::common::rest::{RawCanisterCall, RawCanisterId, RawCheckpoint};
use pocket_ic::{CallError, Request, WasmResult};
use reqwest::{StatusCode, Url};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

const LOCALHOST: &str = "127.0.0.1";

#[test]
fn test_instances_route_with_and_without_backslash_exists() {
    let url = start_server();
    let client = reqwest::blocking::Client::new();

    let response = client.get(url.join("instances/").unwrap()).send().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = client.get(url.join("instances").unwrap()).send().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn test_status() {
    let url = start_server();
    let client = reqwest::blocking::Client::new();

    let response = client.get(url.join("status/").unwrap()).send().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn test_creation_of_instance() {
    let url = start_server();
    let client = reqwest::blocking::Client::new();
    let response = client.post(url.join("instances/").unwrap()).send().unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(!response.text().unwrap().is_empty());
}

#[test]
fn test_invalid_json_during_instance_creation_is_ignored() {
    let url = start_server();
    let client = reqwest::blocking::Client::new();
    let mut payload = HashMap::new();
    payload.insert("this_field_does_not_exist", "foo bar");

    let response = client
        .post(url.join("instances/").unwrap())
        .json(&payload)
        .send()
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let text = response.text().unwrap();
    assert!(!text.is_empty());
    assert!(!text.to_lowercase().contains("foo bar"));
}

#[test]
fn test_call_nonexistent_instance() {
    let url = start_server();
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(url.join("instances/999").unwrap())
        .json("Time")
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(response
        .text()
        .unwrap()
        .to_lowercase()
        .contains("not found"));
}

#[test]
fn test_checkpoint_nonexistent_instance() {
    let url = start_server();
    let client = reqwest::blocking::Client::new();
    let cp = RawCheckpoint {
        checkpoint_name: "my_checkpoint".into(),
    };
    let response = client
        .post(
            url.join("instances/999/tick_and_create_checkpoint")
                .unwrap(),
        )
        .json(&cp)
        .send()
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(response
        .text()
        .unwrap()
        .to_lowercase()
        .contains("not found"));
}

#[test]
fn test_blob_store() {
    let url = start_server();
    let client = reqwest::blocking::Client::new();
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
    let client = reqwest::blocking::Client::new();
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
fn test_restore_from_invalid_checkpoint() {
    let url = start_server();
    let client = reqwest::blocking::Client::new();
    let cp = RawCheckpoint {
        checkpoint_name: "foo bar".into(),
    };

    let response = client
        .post(url.join("instances/").unwrap())
        .json(&cp)
        .send()
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response
        .text()
        .unwrap()
        .to_lowercase()
        .contains("does not exist"));
}

#[test]
fn test_saving_and_loading_checkpoint() {
    let url = start_server();
    let client = reqwest::blocking::Client::new();

    // Create instance A.
    let response = client.post(url.join("instances/").unwrap()).send().unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let instance_id = response.text().unwrap();
    assert!(!instance_id.is_empty());

    // Change state of instance A by creating a canister.
    let call = Request::CanisterUpdateCall(RawCanisterCall {
        sender: Principal::anonymous().as_slice().to_vec(),
        canister_id: Principal::management_canister().as_slice().to_vec(),
        method: "provisional_create_canister_with_cycles".to_string(),
        payload: encode_args((CreateCanisterArgument { settings: None },))
            .expect("failed to encode args"),
    });
    let response = client
        .post(url.join(&format!("instances/{}/", instance_id)).unwrap())
        .json(&call)
        .send()
        .unwrap()
        .text()
        .unwrap();

    let response: Result<WasmResult, CallError> =
        serde_json::from_str(&response).expect("Failed to decode json");
    let canister_id = if let Ok(WasmResult::Reply(bytes)) = response {
        let (CanisterIdRecord { canister_id },) = decode_args(&bytes).unwrap();
        canister_id
    } else {
        panic!("failed to get canister_id")
    };

    // Save a checkpoint of instance A.
    let cp = RawCheckpoint {
        checkpoint_name: "my_cp".into(),
    };
    let response = client
        .post(
            url.join(&format!(
                "instances/{}/tick_and_create_checkpoint/",
                instance_id
            ))
            .unwrap(),
        )
        .json(&cp)
        .send()
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    // List checkpoints.
    let response = client
        .get(url.join("checkpoints/").unwrap())
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let checkpoint_name = response.text().unwrap();
    assert!(checkpoint_name.contains("my_cp"));

    // Create new instance B from the checkpoint.
    let response = client
        .post(url.join("instances/").unwrap())
        .json(&cp)
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let second_instance_id = response.text().unwrap();
    assert!(!second_instance_id.is_empty());

    // List instances.
    let response = client.get(url.join("instances/").unwrap()).send().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let instances = response.text().unwrap();
    assert!(instances.contains(&second_instance_id));

    // Check instance B state: does the canister exist on the new instance?
    let call = Request::CanisterExists(RawCanisterId::from(canister_id));
    let response = client
        .post(
            url.join(&format!("instances/{}/", second_instance_id))
                .unwrap(),
        )
        .json(&call)
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let text = response.text().unwrap();

    assert_eq!(text, "true");
}

#[test]
fn test_deletion_of_instance() {
    let url = start_server();
    let client = reqwest::blocking::Client::new();

    // Create instance.
    let response = client.post(url.join("instances/").unwrap()).send().unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let instance_id = response.text().unwrap();
    assert!(!instance_id.is_empty());

    // Delete instance that was created.
    let response = client
        .delete(url.join(&format!("instances/{}/", instance_id)).unwrap())
        .send()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // List instances and verify the instance is gone.
    let response = client.get(url.join("instances/").unwrap()).send().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let instances = response.text().unwrap();
    assert!(!instances.contains(&instance_id));
}

fn start_server() -> Url {
    let parent_pid = std::os::unix::process::parent_id();
    let bin_path = std::env::var_os("POCKET_IC_BIN").expect("Missing PocketIC binary");
    Command::new(PathBuf::from(bin_path))
        .arg("--pid")
        .arg(parent_pid.to_string())
        .spawn()
        .expect("Failed to start PocketIC binary");
    let port_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.port", parent_pid));
    let ready_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.ready", parent_pid));
    let start = Instant::now();
    loop {
        match ready_file_path.try_exists() {
            Ok(true) => {
                let port_string = std::fs::read_to_string(port_file_path)
                    .expect("Failed to read port from port file");
                let port: u16 = port_string.parse().expect("Failed to parse port to number");
                return Url::parse(&format!("http://{}:{}/", LOCALHOST, port)).unwrap();
            }
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
        if start.elapsed() > Duration::from_secs(5) {
            panic!("Failed to start PocketIC service in time");
        }
    }
}
