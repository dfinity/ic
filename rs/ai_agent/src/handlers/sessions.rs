//! `DELETE /v1/agent/sessions[/:id]` — drop cached chat sessions.
//!
//! Two routes:
//! * `DELETE /v1/agent/sessions/:id` — drop one session.
//! * `DELETE /v1/agent/sessions`     — drop all of them.
//!
//! Both return `200` with `{ "status": "ok", "cleared": <n> }`. The
//! single-id path returns `404` when the id is unknown.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use slog::info;

use crate::{
    models::{ClearResponse, ErrorBody},
    state::AppState,
};

/// Drop one session by id.
pub async fn delete_one(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.sessions.remove(&id) {
        info!(state.log, "session deleted"; "session_id" => &id);
        (
            StatusCode::OK,
            Json(ClearResponse {
                status: "ok",
                cleared: 1,
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorBody::new(format!("unknown session_id: {id}"))),
        )
            .into_response()
    }
}

/// Drop every cached session.
pub async fn delete_all(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cleared = state.sessions.clear();
    info!(state.log, "all sessions cleared"; "count" => cleared);
    (
        StatusCode::OK,
        Json(ClearResponse {
            status: "ok",
            cleared,
        }),
    )
        .into_response()
}
