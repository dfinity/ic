/// This module contains the route handlers for the PocketIc server.
///
/// A handler may receive a representation of a PocketIc Operation in the request
/// body. This has to be canonicalized into a PocketIc Operation before we can
/// deterministically update the PocketIc state machine.
///
use super::state::{InstanceState, OpOut, PocketIcApiState, UpdateReply};
use crate::pocket_ic::Checkpoint;
use crate::pocket_ic::{
    AddCycles, ExecuteIngressMessage, GetCyclesBalance, GetStableMemory, GetTime, Query,
    SetStableMemory, SetTime,
};
use crate::{
    copy_dir,
    pocket_ic::{create_state_machine, PocketIc},
    BindOperation, BlobStore, InstanceId, Operation,
};
use axum::body::HttpBody;
use axum::routing::MethodRouter;
use axum::{
    extract::{self, Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use ic_state_machine_tests::StateMachine;
use ic_types::CanisterId;
use pocket_ic::common::rest::{
    self, ApiResponse, RawAddCycles, RawCanisterCall, RawCanisterId, RawCanisterResult, RawCycles,
    RawSetStableMemory, RawStableMemory, RawTime, RawWasmResult,
};
use pocket_ic::WasmResult;
use serde::Serialize;
use std::sync::atomic::AtomicU64;
use std::{collections::HashMap, sync::Arc};
use tempfile::TempDir;
use tokio::{runtime::Runtime, sync::RwLock, time::Instant};

pub type InstanceMap = Arc<RwLock<HashMap<InstanceId, RwLock<StateMachine>>>>;

pub type ApiState = PocketIcApiState<PocketIc>;

#[derive(Clone)]
pub struct AppState {
    // temporary
    pub instance_map: InstanceMap,
    pub instances_sequence_counter: Arc<AtomicU64>,
    //
    pub api_state: ApiState,
    pub checkpoints: Arc<RwLock<HashMap<String, Arc<TempDir>>>>,
    pub last_request: Arc<RwLock<Instant>>,
    pub runtime: Arc<Runtime>,
    pub blob_store: Arc<dyn BlobStore>,
}

pub fn instance_read_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: extract::FromRef<S>,
{
    Router::new()
        // .route("root_key", get(handler_root_key))
        .directory_route("/query", post(handler_query))
        .directory_route("/get_time", get(handler_get_time))
        .directory_route("/get_cycles", post(handler_get_cycles))
        .directory_route("/get_stable_memory", post(handler_get_stable_memory))
}

pub fn instance_update_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: extract::FromRef<S>,
{
    Router::new()
        .directory_route(
            "/execute_ingress_message",
            post(handler_execute_ingress_message),
        )
        .directory_route("/set_time", post(handler_set_time))
        .directory_route("/add_cycles", post(handler_add_cycles))
        .directory_route("/set_stable_memory", post(handler_set_stable_memory))
        .directory_route("/create_checkpoint", post(handler_create_checkpoint))
}

pub fn instances_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: extract::FromRef<S>,
{
    Router::new()
        //
        // List all IC instances.
        .directory_route("/", get(list_instances))
        //
        // Create a new IC instance. Returns an InstanceId.
        // If the body contains an existing checkpoint name, the instance is restored from that,
        // otherwise a new instance is created.
        .directory_route("/", post(create_instance))
        //
        // Deletes an instance.
        .directory_route("/:id", delete(delete_instance))
        //
        // All the read-only endpoints
        .nest("/:id/read", instance_read_routes())
        //
        // All the state-changing endpoints
        .nest("/:id/update", instance_update_routes())
        //
        // Save this instance to a checkpoint with the given name.
        // Takes a name:String in the request body.
        // TODO: Add a function that separates those two.
        .directory_route(
            "/:id/tick_and_create_checkpoint",
            post(tick_and_create_checkpoint),
        )
    // .nest("/:id/read", instances_read_routes::<S>())
}

async fn run_operation<T: Serialize>(
    api_state: ApiState,
    instance_id: InstanceId,
    op: impl Operation<TargetType = PocketIc> + Send + Sync + 'static,
) -> (StatusCode, ApiResponse<T>)
where
    (StatusCode, ApiResponse<T>): From<OpOut>,
{
    match api_state.update(op.on_instance(instance_id)).await {
        Err(e) => (
            // TODO: what StatusCode should we use here?
            StatusCode::BAD_REQUEST,
            ApiResponse::Error {
                message: format!("{:?}", e),
            },
        ),
        Ok(update_reply) => match update_reply {
            // If the op_id of the ongoing operation is the requested one, we return code 202.
            UpdateReply::Started { state_label, op_id } => (
                StatusCode::ACCEPTED,
                ApiResponse::Started {
                    state_label: format!("{:?}", state_label),
                    op_id: format!("{:?}", op_id),
                },
            ),
            // Otherwise, the instance is busy with a different computation, so we return 409.
            UpdateReply::Busy { state_label, op_id } => (
                StatusCode::CONFLICT,
                ApiResponse::Busy {
                    state_label: format!("{:?}", state_label),
                    op_id: format!("{:?}", op_id),
                },
            ),
            UpdateReply::Output(op_out) => op_out.into(),
        },
    }
}

impl From<OpOut> for (StatusCode, ApiResponse<RawTime>) {
    fn from(value: OpOut) -> Self {
        match value {
            OpOut::Time(time) => (
                StatusCode::OK,
                ApiResponse::Success(RawTime {
                    nanos_since_epoch: time,
                }),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::Error {
                    message: "operation returned invalid type".into(),
                },
            ),
        }
    }
}

impl From<OpOut> for (StatusCode, ApiResponse<()>) {
    fn from(value: OpOut) -> Self {
        match value {
            OpOut::NoOutput => (StatusCode::OK, ApiResponse::Success(())),
            OpOut::Checkpoint(_) => (StatusCode::OK, ApiResponse::Success(())),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::Error {
                    message: "operation returned invalid type".into(),
                },
            ),
        }
    }
}

impl From<OpOut> for (StatusCode, ApiResponse<RawCycles>) {
    fn from(value: OpOut) -> Self {
        match value {
            OpOut::Cycles(cycles) => (StatusCode::OK, ApiResponse::Success(RawCycles { cycles })),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::Error {
                    message: "operation returned invalid type".into(),
                },
            ),
        }
    }
}

impl From<OpOut> for (StatusCode, ApiResponse<RawStableMemory>) {
    fn from(value: OpOut) -> Self {
        match value {
            OpOut::Bytes(stable_memory) => (
                StatusCode::OK,
                ApiResponse::Success(RawStableMemory {
                    blob: stable_memory,
                }),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::Error {
                    message: "operation returned invalid type".into(),
                },
            ),
        }
    }
}

impl From<OpOut> for (StatusCode, ApiResponse<RawCanisterResult>) {
    fn from(value: OpOut) -> Self {
        match value {
            OpOut::CanisterResult(wasm_result) => {
                let inner = match wasm_result {
                    Ok(WasmResult::Reply(wasm_result)) => {
                        RawCanisterResult::Ok(RawWasmResult::Reply(wasm_result))
                    }
                    Ok(WasmResult::Reject(error_message)) => {
                        RawCanisterResult::Ok(RawWasmResult::Reject(error_message))
                    }
                    Err(user_error) => RawCanisterResult::Err(user_error),
                };
                (StatusCode::OK, ApiResponse::Success(inner))
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::Error {
                    message: "operation returned invalid type".into(),
                },
            ),
        }
    }
}

impl From<OpOut> for (StatusCode, ApiResponse<RawCanisterId>) {
    fn from(value: OpOut) -> Self {
        match value {
            OpOut::CanisterId(canister_id) => (
                StatusCode::OK,
                ApiResponse::Success(RawCanisterId {
                    canister_id: canister_id.get().to_vec(),
                }),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::Error {
                    message: "operation returned invalid type".into(),
                },
            ),
        }
    }
}

// ----------------------------------------------------------------------------------------------------------------- //
// Read handlers

pub async fn handler_query(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    extract::Json(raw_canister_call): extract::Json<RawCanisterCall>,
) -> (StatusCode, Json<ApiResponse<RawCanisterResult>>) {
    match crate::pocket_ic::CanisterCall::try_from(raw_canister_call) {
        Ok(canister_call) => {
            let query_op = Query(canister_call);
            // TODO: how to know what run_operation returns, i.e. to what to parse it? (type safety?)
            // (applies to all handlers)
            let (code, response) = run_operation(api_state, instance_id, query_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

pub async fn handler_get_time(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
) -> (StatusCode, Json<ApiResponse<RawTime>>) {
    let time_op = GetTime {};
    let (code, response) = run_operation(api_state, instance_id, time_op).await;
    (code, Json(response))
}

pub async fn handler_get_cycles(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    extract::Json(raw_canister_id): extract::Json<RawCanisterId>,
) -> (StatusCode, Json<ApiResponse<RawCycles>>) {
    match CanisterId::try_from(raw_canister_id.canister_id) {
        Ok(canister_id) => {
            let get_op = GetCyclesBalance { canister_id };
            let (code, response) = run_operation(api_state, instance_id, get_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

pub async fn handler_get_stable_memory(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    axum::extract::Json(raw_canister_id): axum::extract::Json<RawCanisterId>,
) -> (StatusCode, Json<ApiResponse<RawStableMemory>>) {
    match CanisterId::try_from(raw_canister_id.canister_id) {
        Ok(canister_id) => {
            let get_op = GetStableMemory { canister_id };
            let (code, response) = run_operation(api_state, instance_id, get_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

// ----------------------------------------------------------------------------------------------------------------- //
// Update handlers

pub async fn handler_execute_ingress_message(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    extract::Json(raw_canister_call): extract::Json<RawCanisterCall>,
) -> (StatusCode, Json<ApiResponse<RawCanisterResult>>) {
    match crate::pocket_ic::CanisterCall::try_from(raw_canister_call) {
        Ok(canister_call) => {
            let ingress_op = ExecuteIngressMessage(canister_call);
            let (code, response) = run_operation(api_state, instance_id, ingress_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

pub async fn handler_set_time(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    axum::extract::Json(time): axum::extract::Json<rest::RawTime>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    let op = SetTime {
        time: ic_types::Time::from_nanos_since_unix_epoch(time.nanos_since_epoch),
    };
    let (code, response) = run_operation(api_state, instance_id, op).await;
    (code, Json(response))
}

pub async fn handler_add_cycles(
    State(AppState {
        instance_map: _,
        instances_sequence_counter: _,
        api_state,
        checkpoints: _,
        last_request: _,
        runtime: _,
        blob_store: _,
    }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    extract::Json(raw_add_cycles): extract::Json<RawAddCycles>,
) -> (StatusCode, Json<ApiResponse<RawCycles>>) {
    match AddCycles::try_from(raw_add_cycles) {
        Ok(add_op) => {
            let (code, response) = run_operation(api_state, instance_id, add_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

pub async fn handler_set_stable_memory(
    State(AppState {
        instance_map: _,
        instances_sequence_counter: _,
        api_state,
        checkpoints: _,
        last_request: _,
        runtime: _,
        blob_store,
    }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    axum::extract::Json(raw): axum::extract::Json<RawSetStableMemory>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    match SetStableMemory::from_store(raw, blob_store).await {
        Ok(set_op) => {
            let (code, response) = run_operation(api_state, instance_id, set_op).await;
            (code, Json(response))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::Error {
                message: format!("{:?}", e),
            }),
        ),
    }
}

// Only creates a checkpoint and stores the checkpoint dir in the graph;
// does not name it or return anything
pub async fn handler_create_checkpoint(
    State(AppState {
        instance_map: _,
        instances_sequence_counter: _,
        api_state,
        checkpoints: _,
        last_request: _,
        runtime: _,
        blob_store: _,
    }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
) -> (StatusCode, Json<ApiResponse<()>>) {
    println!("creating checkpoint");
    let op = Checkpoint;
    let (code, res) = run_operation(api_state, instance_id, op).await;
    (code, Json(res))
}

// ----------------------------------------------------------------------------------------------------------------- //
// Other handlers

pub async fn status() -> StatusCode {
    StatusCode::OK
}

/// Create a new empty IC instance or restore from checkpoint
/// The new InstanceId will be returned
pub async fn create_instance(
    State(AppState {
        instance_map: _,
        instances_sequence_counter: _,
        api_state,
        checkpoints,
        last_request: _,
        runtime,
        blob_store: _,
    }): State<AppState>,
    body: Option<extract::Json<rest::RawCheckpoint>>,
) -> (StatusCode, Json<rest::CreateInstanceResponse>) {
    let sm = match body {
        None => tokio::task::spawn_blocking(|| create_state_machine(None, runtime))
            .await
            .expect("Failed to launch a state machine"),
        Some(body) => {
            let checkpoints = checkpoints.read().await;
            if !checkpoints.contains_key(&body.checkpoint_name) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(rest::CreateInstanceResponse::Error {
                        message: format!("Checkpoint '{}' does not exist.", body.checkpoint_name),
                    }),
                );
            }
            let proto_dir = checkpoints.get(&body.checkpoint_name).unwrap();
            let new_instance_dir = TempDir::new().expect("Failed to create tempdir");
            copy_dir(proto_dir.path(), new_instance_dir.path())
                .expect("Failed to copy state directory");
            drop(checkpoints);
            // create instance
            tokio::task::spawn_blocking(|| create_state_machine(Some(new_instance_dir), runtime))
                .await
                .expect("Failed to launch a state machine")
        }
    };
    let pocket_ic = PocketIc::new(sm);
    let instance_id = api_state.add_instance(pocket_ic).await;
    (
        StatusCode::CREATED,
        Json(rest::CreateInstanceResponse::Created { instance_id }),
    )
}

pub async fn list_instances(
    State(AppState {
        instance_map: _,
        instances_sequence_counter: _,
        api_state,
        checkpoints: _,
        last_request: _,
        runtime: _,
        blob_store: _,
    }): State<AppState>,
) -> Json<Vec<String>> {
    let instances = api_state.list_instances().await;
    let instances: Vec<String> = instances
        .iter()
        .map(|instance_state| match instance_state {
            InstanceState::Busy { state_label, op_id } => {
                format!("Busy({:?}, {:?})", state_label, op_id)
            }
            InstanceState::Available(_) => "Available".to_string(),
            InstanceState::Deleted => "Deleted".to_string(),
        })
        .collect();
    Json(instances)
}

pub async fn list_checkpoints(
    State(AppState {
        instance_map: _,
        instances_sequence_counter: _,
        api_state: _,
        checkpoints,
        last_request: _,
        runtime: _,
        blob_store: _,
    }): State<AppState>,
) -> Json<Vec<String>> {
    let checkpoints = checkpoints
        .read()
        .await
        .keys()
        .cloned()
        .collect::<Vec<String>>();
    Json(checkpoints)
}

// TODO: Add a function that separates those two.
pub async fn tick_and_create_checkpoint(
    State(AppState {
        instance_map: _,
        instances_sequence_counter: _,
        api_state: _,
        checkpoints: _,
        last_request: _,
        runtime: _,
        blob_store: _,
    }): State<AppState>,
    Path(_id): Path<InstanceId>,
    extract::Json(rest::RawCheckpoint { checkpoint_name: _ }): extract::Json<rest::RawCheckpoint>,
) -> (StatusCode, ()) {
    // Needs an Operation type
    (StatusCode::NOT_FOUND, ())
    // let mut checkpoints = checkpoints.write().await;
    // if checkpoints.contains_key(&payload.checkpoint_name) {
    //     return (
    //         StatusCode::CONFLICT,
    //         format!("Checkpoint {} already exists.", payload.checkpoint_name),
    //     );
    // }
    // let guard_map = instance_map.read().await;
    // if let Some(rw_lock) = guard_map.get(&id) {
    //     let guard_sm = rw_lock.write().await;
    //     // Enable checkpoints and make a tick to write a checkpoint.
    //     guard_sm.set_checkpoints_enabled(true);
    //     guard_sm.tick();
    //     guard_sm.set_checkpoints_enabled(false);
    //     // Copy state directory to named location.
    //     let checkpoint_dir = TempDir::new().expect("Failed to create tempdir");
    //     copy_dir(guard_sm.state_dir.path(), checkpoint_dir.path())
    //         .expect("Failed to copy state directory");
    //     checkpoints.insert(payload.checkpoint_name, Arc::new(checkpoint_dir));
    //     (StatusCode::CREATED, "Checkpoint created.".to_string())
    // } else {
    //     // id not found in map; return error
    //     // TODO: Result Type for this call
    //     (
    //         StatusCode::NOT_FOUND,
    //         format!("Instance with ID {} was not found.", &id),
    //     )
    // }
}

pub async fn delete_instance(
    State(AppState {
        instance_map: _,
        instances_sequence_counter: _,
        api_state,
        checkpoints: _,
        last_request: _,
        runtime: _,
        blob_store: _,
    }): State<AppState>,
    Path(id): Path<InstanceId>,
) -> StatusCode {
    api_state.delete_instance(id).await;
    StatusCode::OK
}

pub trait RouterExt<S, B>
where
    B: HttpBody + Send + 'static,
    S: Clone + Send + Sync + 'static,
{
    fn directory_route(self, path: &str, method_router: MethodRouter<S, B>) -> Self;
}

impl<S, B> RouterExt<S, B> for Router<S, B>
where
    B: HttpBody + Send + 'static,
    S: Clone + Send + Sync + 'static,
{
    fn directory_route(self, path: &str, method_router: MethodRouter<S, B>) -> Self {
        self.route(path, method_router.clone())
            .route(&format!("{path}/"), method_router)
    }
}
