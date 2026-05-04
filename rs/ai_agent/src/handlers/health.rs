use std::sync::Arc;

use axum::{Json, extract::State};

use crate::{models::HealthResponse, state::AppState};

/// `GET /v1/health` — liveness probe; reports active provider/model if any.
pub async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let provider = state.provider.read().await;
    let (provider_name, model) = match provider.as_ref() {
        Some(p) => (Some(p.name().to_string()), Some(p.model().to_string())),
        None => (None, None),
    };
    Json(HealthResponse {
        status: "ok",
        provider: provider_name,
        model,
    })
}
