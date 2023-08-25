use candid::Principal;
use candid::{decode_args, encode_args};
use ic_cdk::api::management_canister::main::{CanisterIdRecord, CreateCanisterArgument};
use pocket_ic::CallError;
use pocket_ic::CanisterCall;
use pocket_ic::RawCanisterId;
use pocket_ic::Request;
use pocket_ic::WasmResult;
use reqwest::Url;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use std::time::Instant;

const POCKET_IC_BIN_PATH: &str = "../../target/debug/pocket-ic-backend";
const LOCALHOST: &str = "127.0.0.1";

// TODO: use asserts. best achieved with a uniform reponse type from the rest-api.
#[test]
fn save_and_load_checkpoint() {
    let url = start_server();
    let client = reqwest::blocking::Client::new();

    println!("Create instance 1");
    let instance_id = client
        .post(url.join("instances").unwrap())
        .send()
        .expect("Failed to get result")
        .text()
        .expect("Failed to get text");
    println!("instance_id: {}", instance_id);

    println!("Change state of instance 1 by creating a canister");
    let call = Request::CanisterUpdateCall(CanisterCall {
        sender: Principal::anonymous().as_slice().to_vec(),
        canister_id: Principal::management_canister().as_slice().to_vec(),
        method: "provisional_create_canister_with_cycles".to_string(),
        arg: encode_args((CreateCanisterArgument { settings: None },))
            .expect("failed to encode args"),
    });
    let res = client
        .post(url.join(&format!("instances/{}", instance_id)).unwrap())
        .json(&call)
        .send()
        .expect("Failed to get result")
        .text()
        .expect("Failed to get text");
    println!("Created canister: {}", res);
    let res: Result<WasmResult, CallError> =
        serde_json::from_str(&res).expect("Failed to decode json");
    let canister_id = if let Ok(WasmResult::Reply(bytes)) = res {
        let (CanisterIdRecord { canister_id },) = decode_args(&bytes).unwrap();
        canister_id
    } else {
        panic!("failed to get canister_id")
    };
    println!("canister_id: {}", canister_id);

    // save a checkpoint from the first instance
    println!("Save a checkpoint from instance 1");
    let res = client
        .post(
            url.join(&format!("instances/{}/save_checkpoint", instance_id))
                .unwrap(),
        )
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body("\"cp1\"") //TODO: use json instead of body and remove header
        .send()
        .expect("Failed to get result")
        .text()
        .expect("Failed to get text");
    println!("checkpointing: {}", res);

    // list checkpoints
    println!("List checkpoints");
    let res = client
        .get(url.join("checkpoints").unwrap())
        .send()
        .expect("Failed to get result")
        .text()
        .expect("Failed to get text");
    println!("checkpoints: {}", res);

    // create new instance from the checkpoint
    println!("Create a new instance 2 from checkpoint");
    let res = client
        .post(url.join("checkpoints/load").unwrap())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body("\"cp1\"")
        .send()
        .expect("Failed to get result")
        .text()
        .expect("Failed to get text");
    let second_inst_id = res.clone();
    println!("instance loaded from checkpoint: {}", res);

    println!(
        "Check instance 2 state: does the canister with id {} exist on instance {}?",
        &canister_id, &second_inst_id,
    );
    let call = Request::CanisterExists(RawCanisterId::from(canister_id));
    let res = client
        .post(url.join(&format!("instances/{}", second_inst_id)).unwrap())
        .json(&call)
        .send()
        .expect("Failed to get result")
        .text()
        .expect("Failed to get text");
    println!("canister exists on instance 2: {}", res);
}

fn start_server() -> Url {
    let parent_pid = std::os::unix::process::parent_id();
    Command::new(PathBuf::from(POCKET_IC_BIN_PATH))
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
                let daemon_url = Url::parse(&format!("http://{}:{}/", LOCALHOST, port)).unwrap();
                println!("Found PocketIC running at {}", daemon_url);
                return daemon_url;
            }
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
        if start.elapsed() > Duration::from_secs(5) {
            panic!("Failed to start PocketIC service in time");
        }
    }
}
