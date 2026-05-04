//! Axum router wiring.

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use tower_http::trace::TraceLayer;

use crate::{
    handlers::{chat::chat, config::configure, health::health, run::run},
    state::AppState,
};

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/config", post(configure))
        .route("/v1/agent/run", post(run))
        .route("/v1/agent/chat", post(chat))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
