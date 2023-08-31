use atomic_counter::{AtomicCounter, ConsistentCounter};
use axum::{
    extract::{Path, State},
    http,
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
    Router, Server,
};
use clap::Parser;
use ic_config::execution_environment;
use ic_config::subnet_config::SubnetConfig;
use ic_crypto::threshold_sig_public_key_to_der;
use ic_crypto_iccsa::types::SignatureBytes;
use ic_crypto_iccsa::{public_key_bytes_from_der, verify};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_types::{CanisterId, Cycles, PrincipalId};
use itertools::Itertools;
use pocket_ic::{CanisterCall, RawCanisterId, Request, Request::*};
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;
use tokio::time::Duration;

const TTL_SEC: u64 = 60;

pub type InstanceId = String;
// The shared, mutable state of the PocketIC process.
// In essence, a Map<InstanceId, StateMachine>, but due to shared mutability, some extra layers are needed.
//
// The outer RwLock is for concurrent read access to the Map (such as calls to different instances),
// and exclusive write access (when a new instance is created or destroyed).
// The inner RwLock should allow safe concurrent calls to the same instance. TODO: Confirm this.
pub type InstanceMap = Arc<RwLock<HashMap<InstanceId, RwLock<StateMachine>>>>;

#[derive(Clone)]
pub struct AppState {
    pub instance_map: InstanceMap,
    pub last_request: Arc<RwLock<Instant>>,
    pub checkpoints: Arc<RwLock<HashMap<String, Arc<TempDir>>>>,
    pub instances_sequence_counter: Arc<ConsistentCounter>,
    pub runtime: Arc<Runtime>,
}

impl axum::extract::FromRef<AppState> for InstanceMap {
    fn from_ref(app_state: &AppState) -> InstanceMap {
        app_state.instance_map.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<RwLock<Instant>> {
    fn from_ref(app_state: &AppState) -> Arc<RwLock<Instant>> {
        app_state.last_request.clone()
    }
}

impl axum::extract::FromRef<AppState> for Arc<RwLock<HashMap<String, Arc<TempDir>>>> {
    fn from_ref(app_state: &AppState) -> Arc<RwLock<HashMap<String, Arc<TempDir>>>> {
        app_state.checkpoints.clone()
    }
}

// Command line arguments to PocketIC server.
#[derive(Parser)]
struct Args {
    #[clap(long)]
    pid: u32,
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(16)
        // we use the tokio rt to dispatch blocking operations in the background
        .max_blocking_threads(16)
        .build()
        .expect("Failed to create tokio runtime!");
    let runtime_arc = Arc::new(rt);
    runtime_arc.block_on(async { start(runtime_arc.clone()).await });
}

async fn start(runtime: Arc<Runtime>) {
    let args = Args::parse();
    let port_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.port", args.pid));
    let ready_file_path = std::env::temp_dir().join(format!("pocket_ic_{}.ready", args.pid));
    let mut new_port_file = match is_first_server(&port_file_path) {
        Ok(f) => f,
        Err(_) => {
            return;
        }
    };
    // This process is the one to start PocketIC.

    // The shared, mutable state of the PocketIC process.
    let instance_map: InstanceMap = Arc::new(RwLock::new(HashMap::new()));
    // A time-to-live mechanism: Requests bump this value, and the server
    // gracefully shuts down when the value wasn't bumped for a while
    let last_request = Arc::new(RwLock::new(Instant::now()));
    let app_state = AppState {
        instance_map,
        last_request,
        checkpoints: Arc::new(RwLock::new(HashMap::new())),
        instances_sequence_counter: ConsistentCounter::new(0).into(),
        runtime,
    };

    let app = Router::new()
        //
        // Get health of service.
        .route("/status", get(status))
        //
        // List all IC instances.
        .route("/instances", get(list_instances))
        //
        // Create a new IC instance. Returns an InstanceId.
        // Body is currently ignored.
        .route("/instances", post(create_instance))
        //
        // Call the specified IC instance.
        // Body contains a Request.
        // Returns the IC's Response.
        .route("/instances/:id", post(call_instance))
        //
        // Save this instance to a checkpoint with the given name.
        // Takes a name:String in the request body.
        .route("/instances/:id/save_checkpoint", post(save_checkpoint))
        //
        // List all checkpoints.
        .route("/checkpoints", get(list_checkpoints))
        //
        // Creates a new instance from an existing checkpoint.
        // Takes a name:String in the request body.
        // Returns an instance_id.
        .route("/checkpoints/load", post(load_checkpoint))
        //
        // Deletes an instance.
        .route("/instances/:id/delete", delete(delete_instance))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            bump_last_request_timestamp,
        ))
        .with_state(app_state.clone());

    // bind to port 0; the OS will give a specific port; communicate that to parent process
    let server = Server::bind(&"127.0.0.1:0".parse().expect("Failed to parse address"))
        .serve(app.into_make_service());
    let real_port = server.local_addr().port();
    let _ = new_port_file.write_all(real_port.to_string().as_bytes());
    let _ = new_port_file.flush();

    let ready_file = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&ready_file_path);
    if ready_file.is_ok() {
        println!("The PocketIC server is listening on port {}", real_port);
    } else {
        eprintln!("The .ready file already exists; This should not happen unless the PID has been reused, and/or the tmp dir has not been properly cleaned up");
    }

    // This is a safeguard against orphaning this child process.
    let shutdown_signal = async {
        loop {
            let guard = app_state.last_request.read().await;
            if guard.elapsed() > Duration::from_secs(TTL_SEC) {
                break;
            }
            drop(guard);
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        println!("The PocketIC server will terminate");
        // Clean up tmpfiles.
        let _ = std::fs::remove_file(ready_file_path);
        let _ = std::fs::remove_file(port_file_path);
    };
    let server = server.with_graceful_shutdown(shutdown_signal);
    server.await.expect("Failed to launch the PocketIC server");
}

/// Returns the opened file if it was successfully created and is readable, writeable. Otherwise,
/// returns an error. Used to determine if this is the first process creating this file.
fn is_first_server<P: AsRef<std::path::Path>>(port_file_path: P) -> std::io::Result<File> {
    // .create_new(true) ensures atomically that this file was created newly, and gives an error otherwise.
    File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&port_file_path)
}

async fn bump_last_request_timestamp<B>(
    State(last_update): State<Arc<RwLock<Instant>>>,
    request: http::Request<B>,
    next: Next<B>,
) -> Response {
    *last_update.write().await = Instant::now();
    next.run(request).await
}

fn create_state_machine(state_dir: Option<TempDir>, runtime: Arc<Runtime>) -> StateMachine {
    let hypervisor_config = execution_environment::Config {
        default_provisional_cycles_balance: Cycles::new(0),
        ..Default::default()
    };
    let config = StateMachineConfig::new(SubnetConfig::new(SubnetType::System), hypervisor_config);
    if let Some(state_dir) = state_dir {
        StateMachineBuilder::new()
            .with_config(Some(config))
            .with_checkpoints_enabled(true)
            .with_state_dir(state_dir)
            .with_runtime(runtime)
            .build()
    } else {
        StateMachineBuilder::new()
            .with_config(Some(config))
            .with_checkpoints_enabled(true)
            .with_runtime(runtime)
            .build()
    }
}

fn copy_dir(
    src: impl AsRef<std::path::Path>,
    dst: impl AsRef<std::path::Path>,
) -> std::io::Result<()> {
    std::fs::create_dir_all(&dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------------------------------------------------- //
// Route handlers

async fn status() -> StatusCode {
    StatusCode::OK
}

/// Create a new IC instance.
/// The new InstanceId will be returned
async fn create_instance(
    State(AppState {
        instance_map,
        last_request: _,
        checkpoints: _,
        instances_sequence_counter: counter,
        runtime,
    }): State<AppState>,
) -> String {
    let sm = tokio::task::spawn_blocking(|| create_state_machine(None, runtime))
        .await
        .expect("Failed to launch a state machine");
    let mut guard = instance_map.write().await;
    let instance_id = counter.inc().to_string();
    guard.insert(instance_id.clone(), RwLock::new(sm));
    instance_id
}

async fn list_instances(State(inst_map): State<InstanceMap>) -> String {
    let map_guard = inst_map.read().await;
    map_guard.keys().join(", ")
}

#[allow(clippy::type_complexity)]
async fn list_checkpoints(
    State(checkpoints): State<Arc<RwLock<HashMap<String, Arc<TempDir>>>>>,
) -> String {
    let checkpoints = checkpoints.read().await;
    checkpoints.keys().join(", ")
}

// Call the IC instance with the given InstanceId
async fn call_instance(
    State(inst_map): State<InstanceMap>,
    Path(id): Path<InstanceId>,
    axum::extract::Json(request): axum::extract::Json<Request>,
) -> (StatusCode, String) {
    let guard_map = inst_map.read().await;
    if let Some(rw_lock) = guard_map.get(&id) {
        let guard_sm = rw_lock.write().await;
        (StatusCode::OK, call_sm(&guard_sm, request))
    } else {
        (
            StatusCode::NOT_FOUND,
            format!("Instance with ID {} was not found.", &id),
        )
    }
}

async fn save_checkpoint(
    State(AppState {
        instance_map,
        last_request: _,
        checkpoints,
        ..
    }): State<AppState>,
    Path(id): Path<InstanceId>,
    axum::extract::Json(checkpoint_name): axum::extract::Json<String>,
) -> (StatusCode, String) {
    let mut checkpoints = checkpoints.write().await;
    if checkpoints.contains_key(&checkpoint_name) {
        return (
            StatusCode::CONFLICT,
            format!("Checkpoint {} already exists.", checkpoint_name),
        );
    }
    let guard_map = instance_map.read().await;
    if let Some(rw_lock) = guard_map.get(&id) {
        let guard_sm = rw_lock.write().await;
        // copy state directory to named location
        let checkpoint_dir = TempDir::new().expect("Failed to create tempdir");
        copy_dir(guard_sm.state_dir.path(), checkpoint_dir.path())
            .expect("Failed to copy state directory");
        checkpoints.insert(checkpoint_name, Arc::new(checkpoint_dir));
        (StatusCode::OK, "Success".to_string())
    } else {
        // id not found in map; return error
        // TODO: Result Type for this call
        (
            StatusCode::NOT_FOUND,
            format!("Instance with ID {} was not found.", &id),
        )
    }
}

async fn load_checkpoint(
    State(AppState {
        instance_map,
        last_request: _,
        checkpoints,
        instances_sequence_counter: counter,
        runtime,
    }): State<AppState>,
    axum::extract::Json(checkpoint_name): axum::extract::Json<String>,
) -> (StatusCode, String) {
    let checkpoints = checkpoints.read().await;
    if !checkpoints.contains_key(&checkpoint_name) {
        return (
            StatusCode::NOT_FOUND,
            format!("Checkpoint {} does not exist.", checkpoint_name),
        );
    }
    let proto_dir = checkpoints.get(&checkpoint_name).unwrap();
    let new_instance_dir = TempDir::new().expect("Failed to create tempdir");
    copy_dir(proto_dir.path(), new_instance_dir.path()).expect("Failed to copy state directory");
    drop(checkpoints);
    // create instance
    let sm = tokio::task::spawn_blocking(|| create_state_machine(Some(new_instance_dir), runtime))
        .await
        .expect("Failed to launch a state machine");
    let mut instance_map = instance_map.write().await;
    let instance_id = counter.inc().to_string();
    instance_map.insert(instance_id.clone(), RwLock::new(sm));
    (StatusCode::OK, instance_id)
}

async fn delete_instance(
    State(instance_map): State<InstanceMap>,
    Path(id): Path<InstanceId>,
) -> StatusCode {
    let mut guard = instance_map.write().await;
    let _ = guard.remove(&id);
    StatusCode::OK
}

// ----------------------------------------------------------------------------------------------------------------- //
// Code borrowed and adapted from rs/state_machine_tests/src/main.rs

fn call_sm(sm: &StateMachine, data: Request) -> String {
    match data {
        RootKey => to_json_str(threshold_sig_public_key_to_der(sm.root_key()).unwrap()),
        Time => to_json_str(sm.time()),
        SetTime(time) => {
            sm.set_time(time);
            to_json_str(())
        }
        AdvanceTime(amount) => {
            sm.advance_time(amount);
            to_json_str(())
        }
        CanisterUpdateCall(call) => {
            let mut call = ParsedCanisterCall::from(call);
            if call.canister_id == CanisterId::ic_00() && call.method == "create_canister" {
                call.method = "provisional_create_canister_with_cycles".to_string();
            }
            let result =
                sm.execute_ingress_as(call.sender, call.canister_id, call.method, call.arg);
            to_json_str(result)
        }
        CanisterQueryCall(call) => {
            let call = ParsedCanisterCall::from(call);
            let result = sm.query_as(call.sender, call.canister_id, call.method, call.arg);
            to_json_str(result)
        }
        CanisterExists(canister_id) => to_json_str(sm.canister_exists(to_canister_id(canister_id))),
        SetStableMemory(arg) => {
            let canister_id = CanisterId::try_from(arg.canister_id).expect("invalid canister id");
            sm.set_stable_memory(canister_id, arg.data.as_ref());
            to_json_str(())
        }
        ReadStableMemory(canister_id) => to_json_str(sm.stable_memory(to_canister_id(canister_id))),
        CyclesBalance(canister_id) => to_json_str(sm.cycle_balance(to_canister_id(canister_id))),
        AddCycles(arg) => to_json_str(sm.add_cycles(
            CanisterId::try_from(arg.canister_id).expect("invalid canister id"),
            arg.amount,
        )),
        Tick => {
            sm.tick();
            to_json_str(())
        }
        RunUntilCompletion(arg) => {
            sm.run_until_completion(arg.max_ticks as usize);
            to_json_str(())
        }
        VerifyCanisterSig(arg) => {
            type VerificationResult = Result<(), String>;
            let pubkey = match public_key_bytes_from_der(&arg.pubkey) {
                Ok(pubkey) => pubkey,
                Err(err) => {
                    return to_json_str(VerificationResult::Err(format!(
                        "failed to parse DER encoded public key: {:?}",
                        err
                    )));
                }
            };
            let root_pubkey = match parse_threshold_sig_key_from_der(&arg.root_pubkey) {
                Ok(root_pubkey) => root_pubkey,
                Err(err) => {
                    return to_json_str(VerificationResult::Err(format!(
                        "failed to parse DER encoded root public key: {:?}",
                        err
                    )));
                }
            };
            match verify(&arg.msg, SignatureBytes(arg.sig), pubkey, &root_pubkey) {
                Ok(()) => to_json_str(VerificationResult::Ok(())),
                Err(err) => to_json_str(VerificationResult::Err(format!(
                    "canister signature verification failed: {:?}",
                    err
                ))),
            }
        }
    }
}

fn to_json_str<R: Serialize>(response: R) -> String {
    serde_json::to_string(&response).expect("Failed to serialize to json")
}

fn to_canister_id(raw_id: RawCanisterId) -> CanisterId {
    CanisterId::try_from(raw_id.canister_id).expect("invalid canister id")
}

struct ParsedCanisterCall {
    sender: PrincipalId,
    canister_id: CanisterId,
    method: String,
    arg: Vec<u8>,
}

impl From<CanisterCall> for ParsedCanisterCall {
    fn from(call: CanisterCall) -> Self {
        ParsedCanisterCall {
            sender: PrincipalId::try_from(&call.sender).unwrap_or_else(|err| {
                panic!(
                    "failed to parse sender from bytes {}: {}",
                    hex::encode(&call.sender),
                    err
                )
            }),
            canister_id: CanisterId::try_from(&call.canister_id).unwrap_or_else(|err| {
                panic!(
                    "failed to parse canister id from bytes {}: {}",
                    hex::encode(&call.canister_id),
                    err
                )
            }),
            method: call.method,
            arg: call.arg,
        }
    }
}
