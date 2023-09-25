/// This module contains the route handlers for the PocketIc server.
///
/// A handler may receive a representation of a PocketIc Operation in the request
/// body. This has to be canonicalized into a PocketIc Operation before we can
/// deterministically update the PocketIc state machine.
///
use super::state::{InstanceState, PocketIcApiState, UpdateReply};
use crate::pocket_ic::{
    ExecuteIngressMessage, GetStableMemory, GetTime, Query, SetStableMemory, SetTime,
};
use crate::{
    copy_dir,
    pocket_ic::{create_state_machine, PocketIc},
    InstanceId,
};
use crate::{BindOperation, BlobStore, Operation};
use axum::{
    extract::{self, Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use ic_state_machine_tests::StateMachine;
use ic_types::CanisterId;
use pocket_ic::common::rest::{self, RawCanisterCall, RawSetStableMemory};
use pocket_ic::RawCanisterId;
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
        .route("/query", post(handler_query))
        .route("/get_time", get(handler_get_time))
        .route("/get_cycles", post(handler_get_cycles))
        .route("/get_stable_memory", post(handler_get_stable_memory))
}

pub fn instance_update_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: extract::FromRef<S>,
{
    Router::new()
        .route(
            "/execute_ingress_message",
            post(handler_execute_ingress_message),
        )
        .route("/set_time", post(handler_set_time))
        .route("/add_cycles", post(handler_add_cycles))
        .route("/set_stable_memory", post(handler_set_stable_memory))
        .route(
            "/install_canister_as_controller",
            post(handler_install_canister_as_controller),
        )
}

pub fn instances_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AppState: extract::FromRef<S>,
{
    Router::new()
        //
        // List all IC instances.
        .route("/", get(list_instances))
        //
        // Create a new IC instance. Returns an InstanceId.
        // If the body contains an existing checkpoint name, the instance is restored from that,
        // otherwise a new instance is created.
        .route("/", post(create_instance))
        //
        // Deletes an instance.
        .route("/:id", delete(delete_instance))
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
        .route(
            "/:id/tick_and_create_checkpoint",
            post(tick_and_create_checkpoint),
        )
    // .nest("/:id/read", instances_read_routes::<S>())
}

async fn run_operation(
    api_state: ApiState,
    instance_id: InstanceId,
    op: impl Operation<TargetType = PocketIc> + Send + Sync + 'static,
) -> (StatusCode, String) {
    match api_state.update(op.on_instance(instance_id)).await {
        Err(e) => (StatusCode::BAD_REQUEST, format!("{:?}", e)),
        Ok(update_reply) => match update_reply {
            // If the op_id of the ongoing operation is the requested one, we return code 201.
            started @ UpdateReply::Started { .. } => {
                (StatusCode::CREATED, format!("{:?}", started))
            }
            // Otherwise, the instance is busy with a different computation, so we return 409.
            busy @ UpdateReply::Busy { .. } => (StatusCode::CONFLICT, format!("{:?}", busy)),
            UpdateReply::Output(op_out) => {
                (StatusCode::OK, serde_json::to_string(&op_out).unwrap())
            }
        },
    }
}

// ----------------------------------------------------------------------------------------------------------------- //
// Read handlers

pub async fn handler_query(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    extract::Json(raw_canister_call): extract::Json<RawCanisterCall>,
) -> (StatusCode, String) {
    match crate::pocket_ic::CanisterCall::try_from(raw_canister_call) {
        Err(_) => (StatusCode::BAD_REQUEST, "Badly formatted Query".to_string()),
        Ok(canister_call) => {
            let query_op = Query(canister_call);
            run_operation(api_state, instance_id, query_op).await
        }
    }
}

pub async fn handler_get_time(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
) -> (StatusCode, String) {
    let time_op = GetTime {};
    run_operation(api_state, instance_id, time_op).await
}

pub async fn handler_get_cycles(
    State(AppState { .. }): State<AppState>,
    Path(_id): Path<InstanceId>,
    extract::Json(()): extract::Json<()>,
) -> (StatusCode, ()) {
    (StatusCode::NOT_FOUND, ())
}

pub async fn handler_get_stable_memory(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    axum::extract::Json(raw_canister_id): axum::extract::Json<RawCanisterId>,
) -> (StatusCode, String) {
    match CanisterId::try_from(raw_canister_id.canister_id) {
        Ok(canister_id) => {
            let get_op = GetStableMemory { canister_id };
            run_operation(api_state, instance_id, get_op).await
        }
        Err(e) => (StatusCode::BAD_REQUEST, format!("{:?}", e)),
    }
}

// ----------------------------------------------------------------------------------------------------------------- //
// Update handlers

pub async fn handler_execute_ingress_message(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    extract::Json(raw_canister_call): extract::Json<RawCanisterCall>,
) -> (StatusCode, String) {
    match crate::pocket_ic::CanisterCall::try_from(raw_canister_call) {
        Err(_) => (
            StatusCode::BAD_REQUEST,
            "Badly formatted IngressMessage".to_string(),
        ),
        Ok(canister_call) => {
            let ingress_op = ExecuteIngressMessage(canister_call);
            run_operation(api_state, instance_id, ingress_op).await
        }
    }
}

pub async fn handler_set_time(
    State(AppState { api_state, .. }): State<AppState>,
    Path(instance_id): Path<InstanceId>,
    axum::extract::Json(time): axum::extract::Json<rest::RawTime>,
) -> (StatusCode, String) {
    let op = SetTime {
        time: ic_types::Time::from_nanos_since_unix_epoch(time.nanos_since_epoch),
    };
    run_operation(api_state, instance_id, op).await
}

pub async fn handler_add_cycles(
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
    extract::Json(()): extract::Json<()>,
) -> (StatusCode, ()) {
    (StatusCode::NOT_FOUND, ())
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
) -> (StatusCode, String) {
    match SetStableMemory::from_store(raw, blob_store).await {
        Ok(set_op) => run_operation(api_state, instance_id, set_op).await,
        Err(e) => (StatusCode::BAD_REQUEST, format!("{:?}", e)),
    }
}

pub async fn handler_install_canister_as_controller(
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
    extract::Json(()): extract::Json<()>,
) -> (StatusCode, ()) {
    (StatusCode::NOT_FOUND, ())
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
    body: Option<extract::Json<rest::Checkpoint>>,
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
) -> String {
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
    serde_json::to_string(&instances).unwrap()
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
) -> String {
    let checkpoints = checkpoints
        .read()
        .await
        .keys()
        .cloned()
        .collect::<Vec<String>>();
    serde_json::to_string(&checkpoints).unwrap()
}

// Call the IC instance with the given InstanceId
// pub async fn call_instance(
//     State(AppState {
//         api_state,
//         checkpoints: _,
//         last_request: _,
//         runtime: _,
//     }): State<AppState>,
//     Path(id): Path<InstanceId>,
//     extract::Json(request): extract::Json<Request>,
// ) -> (StatusCode, String) {
//     let guard_map = todo!();
// let guard_map = inst_map.read().await;
// if let Some(rw_lock) = guard_map.get(&id) {
//     let guard_sm = rw_lock.write().await;
//     (StatusCode::OK, call_sm(&guard_sm, request))
// } else {
//     (
//         StatusCode::NOT_FOUND,
//         format!("Instance with ID {} was not found.", &id),
//     )
// }
// }

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
    extract::Json(rest::Checkpoint { checkpoint_name: _ }): extract::Json<rest::Checkpoint>,
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
    match api_state.delete_instance(id).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::NOT_FOUND,
    }
}
