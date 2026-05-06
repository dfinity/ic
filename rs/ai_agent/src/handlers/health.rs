use std::sync::Arc;

use axum::{Json, extract::State};

use crate::{models::HealthResponse, state::AppState};

/// `GET /v1/health` — liveness probe; reports active provider/model if any.
pub async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    // A poisoned provider lock can only happen if a panic occurred
    // while it was held write-locked, which would mean the process
    // is in a degraded state already; in that case it's still
    // sensible to report "ok" with no provider so liveness probes
    // can detect the degraded state via the missing fields.
    let provider = state.provider.read().ok();
    let (provider_name, model) = match provider.as_deref().and_then(|opt| opt.as_ref()) {
        Some(p) => (Some(p.name().to_string()), Some(p.model().to_string())),
        None => (None, None),
    };
    Json(HealthResponse {
        status: "ok",
        provider: provider_name,
        model,
    })
}
