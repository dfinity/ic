//! Axum router wiring.

use std::sync::Arc;

use axum::{
    Router,
    routing::{delete, get, post},
};
use tower_http::trace::TraceLayer;

use crate::{
    handlers::{
        chat::chat,
        config::configure,
        health::health,
        run::run,
        sessions::{delete_all as delete_all_sessions, delete_one as delete_one_session},
        tools::{get_tools, set_tools},
    },
    state::AppState,
};

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/config", post(configure))
        // Read / replace the server-wide default tool set. Tools are
        // disabled by default; POST a JSON `{"tools": ["calculator", ...]}`
        // to enable, or `{"tools": []}` to disable.
        .route("/v1/tools", get(get_tools).post(set_tools))
        .route("/v1/agent/run", post(run))
        .route("/v1/agent/chat", post(chat))
        // Drop a single chat session (404 if unknown).
        .route("/v1/agent/sessions/{id}", delete(delete_one_session))
        // Wipe every cached session at once.
        .route("/v1/agent/sessions", delete(delete_all_sessions))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
