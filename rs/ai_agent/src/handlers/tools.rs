//! `GET /v1/tools` and `POST /v1/tools` — read and update the
//! server-wide default tool set used when a request omits its own
//! `tools` field.

use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use slog::info;

use crate::{
    models::{ErrorBody, ToolsConfigRequest, ToolsConfigResponse},
    state::AppState,
    tools::{registered_tool_names, validate_tool_names},
};

/// `GET /v1/tools` — current default tool set + all known tool names.
pub async fn get_tools(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let defaults = read_defaults(&state);
    (
        StatusCode::OK,
        Json(ToolsConfigResponse {
            default_tools: defaults,
            available_tools: registered_tool_names().to_vec(),
        }),
    )
        .into_response()
}

/// `POST /v1/tools` — replace the server-wide default tool set.
///
/// Validates every name against the registry; rejects with 400 on the
/// first unknown name. Pass an empty list to disable tools by default.
pub async fn set_tools(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ToolsConfigRequest>,
) -> impl IntoResponse {
    if let Err(unknown) = validate_tool_names(&req.tools) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody::new(format!("unknown tool: {unknown}"))),
        )
            .into_response();
    }

    // Sync RwLock; no `.await` while the guard is alive. Recover from a
    // poisoned lock the same way `/v1/config` does — by overwriting.
    let new_tools = req.tools.clone();
    match state.default_tools.write() {
        Ok(mut g) => *g = new_tools,
        Err(poisoned) => *poisoned.into_inner() = new_tools,
    }

    info!(state.log, "default tools updated"; "tools" => ?req.tools);

    (
        StatusCode::OK,
        Json(ToolsConfigResponse {
            default_tools: req.tools,
            available_tools: registered_tool_names().to_vec(),
        }),
    )
        .into_response()
}

/// Snapshot the current default tool list. Cheap (`Vec<String>` clone).
/// A poisoned lock is treated as "no defaults" — the request can still
/// run with no tools, which is the safe fallback.
pub fn read_defaults(state: &Arc<AppState>) -> Vec<String> {
    match state.default_tools.read() {
        Ok(g) => g.clone(),
        Err(_) => Vec::new(),
    }
}
