#![allow(deprecated)]
use crate::common::{send_signal_to_pic, start_server, start_server_helper};
use candid::{Encode, Principal};
use ic_agent::agent::CallResponse;
use ic_cdk::api::management_canister::main::CanisterIdRecord;
use ic_cdk::api::management_canister::provisional::ProvisionalCreateCanisterWithCyclesArgument;
use ic_management_canister_types_private::ProvisionalCreateCanisterWithCyclesArgs;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_utils::interfaces::ManagementCanister;
use nix::sys::signal::Signal;
use pocket_ic::common::rest::{InstanceConfig, SubnetConfigSet, SubnetKind};
use pocket_ic::{PocketIc, PocketIcBuilder, PocketIcState, update_candid};
use reqwest::StatusCode;
use reqwest::blocking::Client;
use slog::Level;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;

mod common;

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
    assert_eq!(u32::from_le_bytes(res.try_into().unwrap()), expected_ctr);
}

fn deploy_counter_canister(pic: &PocketIc, canister_id: Principal, counter: u32) {
    const INIT_CYCLES: u128 = 2_000_000_000_000;
    pic.add_cycles(canister_id, INIT_CYCLES);
    let counter_wasm = wat::parse_str(COUNTER_WAT).unwrap();
    pic.install_canister(canister_id, counter_wasm, vec![], None);

    // Bump the counter and check the counter value.
    for _ in 0..counter {
        pic.update_call(canister_id, Principal::anonymous(), "write", vec![])
            .unwrap();
    }
    check_counter(pic, canister_id, counter);
}

fn deploy_counter_canister_to_any_subnet(pic: &PocketIc) -> Principal {
    let canister_id = pic.create_canister();

    deploy_counter_canister(pic, canister_id, 0);

    canister_id
}

fn deploy_counter_canister_to_id(pic: &PocketIc, canister_id: Principal, counter: u32) {
    let actual_canister_id = pic
        .create_canister_with_id(None, None, canister_id)
        .unwrap();
    assert_eq!(actual_canister_id, canister_id);

    deploy_counter_canister(pic, canister_id, counter);
}

fn deploy_counter_canister_to_subnet(
    pic: &PocketIc,
    subnet_id: Principal,
    counter: u32,
) -> Principal {
    let canister_id = pic.create_canister_on_subnet(None, None, subnet_id);

    deploy_counter_canister(pic, canister_id, counter);

    canister_id
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
        http_gateway_config: None,
        state_dir: None,
        icp_config: None,
        log_level: None,
        bitcoind_addr: None,
        dogecoind_addr: None,
        icp_features: None,
        incomplete_state: None,
        initial_time: None,
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

    assert!(
        response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .is_none()
    );

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
    assert!(
        response
            .text()
            .unwrap()
            .to_lowercase()
            .contains("bad encoding")
    );
}

#[test]
fn test_port_file() {
    // tests the port file by setting the parent PID to None in start_server_helper
    start_server_helper(None, None, false, false);
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
            .with_url(endpoint)
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
    let (server_url, _) = start_server_helper(None, None, false, false);
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .with_server_url(server_url.clone())
        .build();

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
fn canister_and_replica_logs() {
    const INIT_CYCLES: u128 = 2_000_000_000_000;
    let (server_url, mut out) = start_server_helper(None, None, true, true);
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
    let (server_url, mut out) = start_server_helper(None, None, true, true);
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

/// Tests that the PocketIC topology and canister states
/// can be successfully restored from a `state_dir`
/// if a PocketIC instance is created with that `state_dir`,
/// using `with_state_dir` on `PocketIcBuilder`.
/// Furthermore, tests that the NNS and application subnets and their canister states
/// can be successfully restored from the respective subnet states,
/// using `with_nns_state` and `with_subnet_state` on `PocketIcBuilder`.
#[test]
fn canister_state_dir_with_graceful_shutdown() {
    canister_state_dir(None);
}

/// Tests that the PocketIC topology and canister states
/// can be successfully restored from a `state_dir`
/// after the PocketIC server has received SIGINT.
#[test]
fn canister_state_dir_with_sigint() {
    canister_state_dir(Some(Signal::SIGINT));
}

/// Tests that the PocketIC topology and canister states
/// can be successfully restored from a `state_dir`
/// after the PocketIC server has received SIGTERM.
#[test]
fn canister_state_dir_with_sigterm() {
    canister_state_dir(Some(Signal::SIGTERM));
}

fn canister_state_dir(shutdown_signal: Option<Signal>) {
    // Create a temporary state directory persisted throughout the test.
    let state_dir = TempDir::new().unwrap();
    let state_dir_path_buf = state_dir.path().to_path_buf();

    // Create a PocketIC instance with NNS and app subnets.
    let (server_url, child) = start_server_helper(None, None, false, false);
    let pic = PocketIcBuilder::new()
        .with_state_dir(state_dir_path_buf.clone())
        .with_server_url(server_url)
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // Check the registry version.
    // The registry version should be 2 as we have two subnets on the PocketIC instance
    // and every subnet is created at a separate registry version.
    let registry_proto_path = state_dir_path_buf.join("registry.proto");
    let registry_data_provider = ProtoRegistryDataProvider::load_from_file(registry_proto_path);
    assert_eq!(registry_data_provider.latest_version(), 2.into());

    // There is one application subnet in the initial topology.
    let initial_topology = pic.topology();
    assert_eq!(initial_topology.get_app_subnets().len(), 1);

    // We create a counter canister on the NNS subnet.
    let nns_subnet = initial_topology.get_nns().unwrap();
    let nns_canister_id = deploy_counter_canister_to_subnet(&pic, nns_subnet, 2);

    // We create a counter canister on the application subnet.
    let app_subnet = initial_topology.get_app_subnets()[0];
    let app_canister_id = deploy_counter_canister_to_subnet(&pic, app_subnet, 1);

    // We create a counter canister with a "specified" canister ID that exists on the IC mainnet,
    // but belongs to the canister ranges of no subnet on the PocketIC instance.
    let spec_canister_id = Principal::from_text("rimrc-piaaa-aaaao-aaljq-cai").unwrap();
    assert!(pic.get_subnet(spec_canister_id).is_none());
    deploy_counter_canister_to_id(&pic, spec_canister_id, 3);

    // Check the registry version.
    // The registry version should be 3 as we now have three subnets on the PocketIC instance
    // and every subnet is created at a separate registry version.
    let registry_proto_path = state_dir_path_buf.join("registry.proto");
    let registry_data_provider = ProtoRegistryDataProvider::load_from_file(registry_proto_path);
    assert_eq!(registry_data_provider.latest_version(), 3.into());

    // There are two application subnets in the final topology.
    let final_topology = pic.topology();
    assert_eq!(final_topology.get_app_subnets().len(), 2);

    send_signal_to_pic(pic, child, shutdown_signal);

    // Start a new PocketIC server.
    let (new_server_url, child) = start_server_helper(None, None, false, false);

    // Create a PocketIC instance mounting the state created so far.
    let pic = PocketIcBuilder::new()
        .with_server_url(new_server_url)
        .with_state_dir(state_dir_path_buf.clone())
        .build();

    // Check that the topology has been properly restored.
    let restored_topology = pic.topology();
    assert_eq!(restored_topology, final_topology);

    // Check that the canister states have been properly restored.
    check_counter(&pic, nns_canister_id, 2);
    check_counter(&pic, app_canister_id, 1);
    check_counter(&pic, spec_canister_id, 3);

    // Bump the counters on all subnets.
    pic.update_call(nns_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();
    pic.update_call(app_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();
    pic.update_call(spec_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();

    // Check that the counters have been properly updated.
    check_counter(&pic, nns_canister_id, 3);
    check_counter(&pic, app_canister_id, 2);
    check_counter(&pic, spec_canister_id, 4);

    send_signal_to_pic(pic, child, shutdown_signal);

    // Start a new PocketIC server.
    let (newest_server_url, child) = start_server_helper(None, None, false, false);

    // Create a PocketIC instance mounting the NNS and app state created so far.
    let nns_subnet_seed = initial_topology
        .subnet_configs
        .get(&nns_subnet)
        .unwrap()
        .subnet_seed;
    let nns_state_dir = state_dir.path().join(hex::encode(nns_subnet_seed));
    let app_subnet_seed = initial_topology
        .subnet_configs
        .get(&app_subnet)
        .unwrap()
        .subnet_seed;
    let app_state_dir = state_dir.path().join(hex::encode(app_subnet_seed));
    let pic = PocketIcBuilder::new()
        .with_server_url(newest_server_url)
        .with_nns_state(nns_state_dir)
        .with_subnet_state(SubnetKind::Application, app_state_dir)
        .build();

    // We only specified to restore one app subnet.
    let restored_topology = pic.topology();
    assert_eq!(restored_topology.get_app_subnets().len(), 1);

    // Check that the topology has been properly restored.
    let mut updated_final_topology = final_topology.clone();
    // We remove the subnet that was not restored from the final topology.
    updated_final_topology
        .subnet_configs
        .retain(|subnet_id, _| *subnet_id == nns_subnet || *subnet_id == app_subnet);
    assert_eq!(restored_topology, updated_final_topology);

    // Check that the canister states have been properly restored.
    check_counter(&pic, nns_canister_id, 3);
    check_counter(&pic, app_canister_id, 2);

    // Bump the counter on all subnets.
    pic.update_call(nns_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();
    pic.update_call(app_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();

    // Check that the counters have been properly updated.
    check_counter(&pic, nns_canister_id, 4);
    check_counter(&pic, app_canister_id, 3);

    send_signal_to_pic(pic, child, shutdown_signal);

    // Start a new PocketIC server.
    let (new_server_url, child) = start_server_helper(None, None, false, false);

    // Create a temporary state directory persisted throughout the rest of the test.
    let write_state_dir = TempDir::new().unwrap();
    let write_state_dir_path_buf = write_state_dir.path().to_path_buf();

    // Create a PocketIC instance mounting the (read-only) state created so far
    // and persisting the state in a separate (write) state.
    let pic = PocketIcBuilder::new()
        .with_server_url(new_server_url)
        .with_read_only_state(&PocketIcState::new_from_path(state_dir_path_buf.clone()))
        .with_state_dir(write_state_dir_path_buf.clone())
        .build();

    // Check that the topology has been properly restored.
    let restored_topology = pic.topology();
    assert_eq!(restored_topology, final_topology);

    // Check that the canister states have not changed
    // after mounting selected subnets individually.
    check_counter(&pic, nns_canister_id, 3);
    check_counter(&pic, app_canister_id, 2);
    check_counter(&pic, spec_canister_id, 4);

    // Bump the counters on all subnets.
    pic.update_call(nns_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();
    pic.update_call(app_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();
    pic.update_call(spec_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();

    // Check that the counters have been properly updated.
    check_counter(&pic, nns_canister_id, 4);
    check_counter(&pic, app_canister_id, 3);
    check_counter(&pic, spec_canister_id, 5);

    send_signal_to_pic(pic, child, shutdown_signal);

    // Start a new PocketIC server.
    let (new_server_url, child) = start_server_helper(None, None, false, false);

    // Create a PocketIC instance mounting the (read-only) state.
    let pic = PocketIcBuilder::new()
        .with_server_url(new_server_url)
        .with_read_only_state(&PocketIcState::new_from_path(state_dir_path_buf.clone()))
        .build();

    // Check that the canister states have not changed
    // after mounting read-only state and making state changes.
    check_counter(&pic, nns_canister_id, 3);
    check_counter(&pic, app_canister_id, 2);
    check_counter(&pic, spec_canister_id, 4);

    // Bump the counters on all subnets.
    pic.update_call(nns_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();
    pic.update_call(app_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();
    pic.update_call(spec_canister_id, Principal::anonymous(), "write", vec![])
        .unwrap();

    // Check that the counters have been properly updated.
    check_counter(&pic, nns_canister_id, 4);
    check_counter(&pic, app_canister_id, 3);
    check_counter(&pic, spec_canister_id, 5);

    send_signal_to_pic(pic, child, shutdown_signal);

    // Start a new PocketIC server.
    let (new_server_url, child) = start_server_helper(None, None, false, false);

    // Create a PocketIC instance mounting the (read-only) state.
    let pic = PocketIcBuilder::new()
        .with_server_url(new_server_url)
        .with_read_only_state(&PocketIcState::new_from_path(state_dir_path_buf.clone()))
        .build();

    // Check that the canister states have not changed
    // after mounting read-only state and making state changes.
    check_counter(&pic, nns_canister_id, 3);
    check_counter(&pic, app_canister_id, 2);
    check_counter(&pic, spec_canister_id, 4);

    send_signal_to_pic(pic, child, shutdown_signal);

    // Start a new PocketIC server.
    let (new_server_url, child) = start_server_helper(None, None, false, false);

    // Create a PocketIC instance mounting the persisted state created so far.
    let pic = PocketIcBuilder::new()
        .with_server_url(new_server_url)
        .with_read_only_state(&PocketIcState::new_from_path(
            write_state_dir_path_buf.clone(),
        ))
        .build();

    // Check that the canister states have been changed in the persisted state
    // when initializing that state from a read-only state.
    check_counter(&pic, nns_canister_id, 4);
    check_counter(&pic, app_canister_id, 3);
    check_counter(&pic, spec_canister_id, 5);

    send_signal_to_pic(pic, child, shutdown_signal);
}

/// The following test is similar to `canister_state_dir`,
/// but creates two app subnets on the original PocketIC instance
/// and then checks that each of the two app subnets
/// can be separately restored from its state
/// along with creating a new empty subnet.
/// This way, the test ensures that PocketIC properly retrieves
/// the subnet configuration from the state of the subnet
/// (since using the default configuration won't work
/// for at least one of the two subnets) and creates new empty subnets
/// with disjoint canister ranges.
#[test]
fn with_subnet_state() {
    // Create a temporary state directory persisted throughout the test.
    let state_dir = TempDir::new().unwrap();
    let state_dir_path_buf = state_dir.path().to_path_buf();

    // Create a PocketIC instance with NNS and app subnets.
    let (server_url, _) = start_server_helper(None, None, false, false);
    let pic = PocketIcBuilder::new()
        .with_state_dir(state_dir_path_buf.clone())
        .with_server_url(server_url.clone())
        .with_nns_subnet()
        .with_application_subnet()
        .with_application_subnet()
        .build();

    // Retrieve the NNS and app subnets from the topology.
    let topology = pic.topology();
    let nns_subnet = topology.get_nns().unwrap();
    let first_app_subnet = topology.get_app_subnets()[0];
    let second_app_subnet = topology.get_app_subnets()[1];

    // We create a counter canister on each of the two app subnets.
    let first_app_canister_id = deploy_counter_canister_to_subnet(&pic, first_app_subnet, 1);
    let second_app_canister_id = deploy_counter_canister_to_subnet(&pic, second_app_subnet, 2);

    drop(pic);

    for (app_subnet, app_canister_id, counter) in [
        (first_app_subnet, first_app_canister_id, 1),
        (second_app_subnet, second_app_canister_id, 2),
    ] {
        // Create a PocketIC instance mounting the NNS and app state created so far.
        let nns_subnet_seed = topology
            .subnet_configs
            .get(&nns_subnet)
            .unwrap()
            .subnet_seed;
        let nns_state_dir = state_dir.path().join(hex::encode(nns_subnet_seed));
        let app_subnet_seed = topology
            .subnet_configs
            .get(&app_subnet)
            .unwrap()
            .subnet_seed;
        let app_state_dir = state_dir.path().join(hex::encode(app_subnet_seed));
        let pic = PocketIcBuilder::new()
            .with_server_url(server_url.clone())
            .with_nns_state(nns_state_dir)
            .with_subnet_state(SubnetKind::Application, app_state_dir)
            .with_application_subnet()
            .build();

        // We specified to restore one app subnet and create a new empty app subnet.
        let restored_topology = pic.topology();
        assert_eq!(restored_topology.get_app_subnets().len(), 2);

        // Check that the topology has been properly restored.
        assert_eq!(
            restored_topology.subnet_configs.get(&nns_subnet).unwrap(),
            topology.subnet_configs.get(&nns_subnet).unwrap()
        );
        assert_eq!(
            restored_topology.subnet_configs.get(&app_subnet).unwrap(),
            topology.subnet_configs.get(&app_subnet).unwrap()
        );

        check_counter(&pic, app_canister_id, counter);
    }
}

fn create_nns_subnet_state() -> (TempDir, PathBuf) {
    // Create a temporary state directory persisted throughout the test.
    let state_dir = TempDir::new().unwrap();
    let state_dir_path_buf = state_dir.path().to_path_buf();

    // Create a PocketIC instance with a single NNS subnet.
    let pic = PocketIcBuilder::new()
        .with_state_dir(state_dir_path_buf.clone())
        .with_nns_subnet()
        .build();

    // Retrieve the NNS subnet from the topology.
    let topology = pic.topology();
    let nns_subnet = topology.get_nns().unwrap();

    drop(pic);

    let nns_subnet_seed = topology
        .subnet_configs
        .get(&nns_subnet)
        .unwrap()
        .subnet_seed;
    let nns_state_dir = state_dir.path().join(hex::encode(nns_subnet_seed));
    (state_dir, nns_state_dir)
}

fn create_app_subnet_state() -> (TempDir, PathBuf) {
    // Create a temporary state directory persisted throughout the test.
    let state_dir = TempDir::new().unwrap();
    let state_dir_path_buf = state_dir.path().to_path_buf();

    // Create a PocketIC instance with a single app subnet.
    let pic = PocketIcBuilder::new()
        .with_state_dir(state_dir_path_buf.clone())
        .with_application_subnet()
        .build();

    // Retrieve the app subnet from the topology.
    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];

    drop(pic);

    let app_subnet_seed = topology
        .subnet_configs
        .get(&app_subnet)
        .unwrap()
        .subnet_seed;
    let app_state_dir = state_dir.path().join(hex::encode(app_subnet_seed));
    (state_dir, app_state_dir)
}

#[test]
#[should_panic(expected = "Invalid canister ranges.")]
fn with_app_subnet_state_twice() {
    let (_state_dir, app_state_dir) = create_app_subnet_state();

    // Create a PocketIC instance mounting the app state twice.
    let _pic = PocketIcBuilder::new()
        .with_subnet_state(SubnetKind::Application, app_state_dir.clone())
        .with_subnet_state(SubnetKind::Application, app_state_dir)
        .build();
}

#[test]
#[should_panic(
    expected = "The actual subnet canister ranges [CanisterIdRange { start: CanisterId(rwlgt-iiaaa-aaaaa-aaaaa-cai), end: CanisterId(renrk-eyaaa-aaaaa-aaada-cai) }, CanisterIdRange { start: CanisterId(qoctq-giaaa-aaaaa-aaaea-cai), end: CanisterId(n5n4y-3aaaa-aaaaa-p777q-cai) }, CanisterIdRange { start: CanisterId(lxzze-o7777-77777-aaaaa-cai), end: CanisterId(x47dp-5x777-77777-p777q-cai) }] for the subnet kind Application are not disjoint from the canister ranges [CanisterIdRange { start: CanisterId(rwlgt-iiaaa-aaaaa-aaaaa-cai), end: CanisterId(renrk-eyaaa-aaaaa-aaada-cai) }, CanisterIdRange { start: CanisterId(qoctq-giaaa-aaaaa-aaaea-cai), end: CanisterId(n5n4y-3aaaa-aaaaa-p777q-cai) }] for a different subnet kind NNS."
)]
fn with_nns_as_app_subnet_state() {
    let (_state_dir, nns_state_dir) = create_nns_subnet_state();

    // Create a PocketIC instance mounting the NNS state as app state.
    let _pic = PocketIcBuilder::new()
        .with_subnet_state(SubnetKind::Application, nns_state_dir)
        .build();
}

#[test]
#[should_panic(
    expected = "The actual subnet canister ranges [CanisterIdRange { start: CanisterId(lxzze-o7777-77777-aaaaa-cai), end: CanisterId(x47dp-5x777-77777-p777q-cai) }] do not contain the canister ranges [CanisterIdRange { start: CanisterId(rwlgt-iiaaa-aaaaa-aaaaa-cai), end: CanisterId(renrk-eyaaa-aaaaa-aaada-cai) }, CanisterIdRange { start: CanisterId(qoctq-giaaa-aaaaa-aaaea-cai), end: CanisterId(n5n4y-3aaaa-aaaaa-p777q-cai) }] expected for the subnet kind NNS."
)]
fn with_app_as_nns_subnet_state() {
    let (_state_dir, app_state_dir) = create_app_subnet_state();

    // Create a PocketIC instance mounting the app state as NNS state.
    let _pic = PocketIcBuilder::new()
        .with_subnet_state(SubnetKind::NNS, app_state_dir)
        .build();
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

    // Retrieve effective canister id for canister creation.
    let topology = pic.topology();
    let effective_canister_id: Principal = topology.default_effective_canister_id.into();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let agent = ic_agent::Agent::builder()
            .with_url(endpoint)
            .with_http_client(reqwest::Client::new())
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
        // This endpoint returns `CallResponse::Response` if the update call can be processed in less than 10 seconds.
        // Otherwise, this endpoint returns `CallResponse::Poll`.
        // In this test, we want to ensure that PocketIC can produce `CallResponse::Response`.
        loop {
            let response = agent
                .update(
                    &Principal::management_canister(),
                    "provisional_create_canister_with_cycles",
                )
                .with_arg(bytes.clone())
                .with_effective_canister_id(effective_canister_id)
                .call()
                .await
                .unwrap();
            match response {
                CallResponse::Poll(_) => {}
                CallResponse::Response(..) => {
                    break;
                }
            };
        }
    })
}

/// Test that query stats are available via the management canister.
#[test]
fn test_query_stats() {
    // Create PocketIC instance with a single app subnet.
    let pic = PocketIcBuilder::new().with_application_subnet().build();

    // We create a counter canister on the app subnet.
    let canister_id = deploy_counter_canister_to_any_subnet(&pic);

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
    // Create PocketIC instance with one NNS subnet and one app subnet.
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // Retrieve the app subnet from the topology.
    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];

    // We create a counter canister on the app subnet.
    let canister_id = deploy_counter_canister_to_subnet(&pic, app_subnet, 0);

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
    // Create PocketIC instance with one NNS subnet and one app subnet.
    let mut pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();

    // Retrieve the app subnet from the topology.
    let topology = pic.topology();
    let app_subnet = topology.get_app_subnets()[0];

    // We create a counter canister on the app subnet.
    deploy_counter_canister_to_subnet(&pic, app_subnet, 0);

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

#[test]
fn auto_progress() {
    let (server_url, mut out) = start_server_helper(
        None,
        Some("pocket_ic_server=debug,tower_http=info,axum::rejection=trace".to_string()),
        true,
        true,
    );
    let pic = PocketIcBuilder::new()
        .with_application_subnet()
        .with_server_url(server_url)
        .build();

    let t0 = pic.get_time();

    assert!(!pic.auto_progress_enabled());

    // Starting auto progress on the IC => a corresponding log should be made and time should start incresing automatically now.
    pic.auto_progress();

    assert!(pic.auto_progress_enabled());

    loop {
        let mut bytes = [0; 1000];
        let _ = out.stdout.as_mut().unwrap().read(&mut bytes).unwrap();
        let stdout = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!stdout.contains("Stopping auto progress for instance 0."));
        if stdout.contains("Starting auto progress for instance 0.") {
            break;
        }
    }

    loop {
        let t = pic.get_time();
        if t > t0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Stopping auto progress on the IC => a corresponding log should be made.
    pic.stop_progress();

    assert!(!pic.auto_progress_enabled());

    loop {
        let mut bytes = [0; 1000];
        let _ = out.stdout.as_mut().unwrap().read(&mut bytes).unwrap();
        let stdout = String::from_utf8(bytes.to_vec()).unwrap();
        if stdout.contains("Stopping auto progress for instance 0.") {
            break;
        }
    }
}
