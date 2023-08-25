#![allow(dead_code)]
use axum::extract::State;
use axum::routing::post;
use axum::Json;
use axum::{extract::Path, http::StatusCode, routing::get, Router};
use ic_state_machine_tests::StateMachine;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

pub type InstanceId = String;
// The shared, mutable state of the PocketIC process.
// In essence, a Map<InstanceId, StateMachine>, but due to shared mutability, some extra layers are needed.
//
// The outer RwLock is for concurrent read access to the Map (such as calls to different instances),
// and exclusive write access (when a new instance is created or destroyed).
// The inner RwLock should allow safe concurrent calls to the same instance. TODO: Confirm this.
pub type InstanceMap = Arc<RwLock<HashMap<InstanceId, RwLock<StateMachine>>>>;

pub type SharedMockApiState = Arc<MockApiState>;

#[derive(Default)]
pub struct MockApiState {
    last_id: AtomicU64,
}

impl MockApiState {
    fn bump_id(&self) -> u64 {
        self.last_id.fetch_add(1, Ordering::Relaxed)
    }

    fn next_id(&self) -> u64 {
        self.last_id.load(Ordering::Relaxed)
    }
}

#[derive(Clone)]
pub struct AppState {
    pub instance_map: InstanceMap,
    pub last_request: Arc<RwLock<Instant>>,
    pub mock_api_state: SharedMockApiState,
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

impl axum::extract::FromRef<AppState> for SharedMockApiState {
    fn from_ref(app_state: &AppState) -> SharedMockApiState {
        app_state.mock_api_state.clone()
    }
}

pub fn new_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    SharedMockApiState: axum::extract::FromRef<S>,
{
    Router::<S>::new().nest("/instances", instances_routes::<S>())
}

fn instances_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    SharedMockApiState: axum::extract::FromRef<S>,
{
    Router::new()
        .route("/", post(handle_new_instance))
        .route("/:id", get(handle_get_instance))
        .nest("/:id/read", instances_read_routes::<S>())
}

fn instances_read_routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    SharedMockApiState: axum::extract::FromRef<S>,
{
    Router::<S>::new().route("/root_key", get(handle_get_rootkey))
}

async fn handle_new_instance(
    State(api_state): State<SharedMockApiState>,
) -> Result<Json<Instance>, StatusCode> {
    let id = api_state.bump_id();
    Ok(Json(Instance {
        instance: format!("/instance/{id}"),
        state: "beef".into(),
    }))
}

/// For now, this handle just returns a mock result.
async fn handle_get_instance(
    State(api_state): State<SharedMockApiState>,
    Path(id): Path<u64>,
) -> Result<Json<Instance>, StatusCode> {
    if id < api_state.next_id() {
        return Ok(Json(Instance {
            instance: format!("/instance/{id}"),
            state: "beef".into(),
        }));
    }
    Err(StatusCode::NOT_FOUND)
}

async fn handle_get_rootkey() {}

#[derive(Serialize)]
struct Instance {
    instance: String,
    state: String,
}
