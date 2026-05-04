use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use slog::{info, warn};

use crate::{
    config::{ConfigRequest, ConfigResponse},
    models::ErrorBody,
    providers::AiProvider,
    state::AppState,
};

/// `POST /v1/config` — install/replace the active provider client.
///
/// Until this endpoint is called successfully, `/v1/agent/run` and
/// `/v1/agent/chat` return 503.
pub async fn configure(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConfigRequest>,
) -> impl IntoResponse {
    match AiProvider::from_request(&req, &state.config.default_model) {
        Ok(provider) => {
            let resp = ConfigResponse {
                status: "ok",
                provider: provider.name().to_string(),
                model: provider.model().to_string(),
            };
            *state.provider.write().await = Some(provider);
            info!(
                state.log,
                "provider configured";
                "provider" => &resp.provider,
                "model" => &resp.model
            );
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => {
            warn!(state.log, "provider config rejected"; "error" => %e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody::new(format!("invalid config: {e}"))),
            )
                .into_response()
        }
    }
}
