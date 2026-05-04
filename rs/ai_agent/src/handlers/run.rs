use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use rig::completion::Prompt;
use slog::warn;

use crate::{
    models::{ErrorBody, RunRequest, RunResponse},
    providers::provider_not_configured,
    state::AppState,
    tools::validate_tool_names,
};

/// Render the full `Error::source()` chain of `e` as " -> "-separated text.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut parts = Vec::new();
    let mut cur: Option<&dyn std::error::Error> = e.source();
    while let Some(s) = cur {
        parts.push(s.to_string());
        cur = s.source();
    }
    parts.join(" -> ")
}

/// `POST /v1/agent/run` — single-turn agent invocation.
pub async fn run(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RunRequest>,
) -> impl IntoResponse {
    if req.prompt.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody::new("prompt must not be empty")),
        )
            .into_response();
    }
    if let Err(unknown) = validate_tool_names(&req.tools) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody::new(format!("unknown tool: {unknown}"))),
        )
            .into_response();
    }

    let provider_guard = state.provider.read().await;
    let provider = match provider_guard.as_ref() {
        Some(p) => p.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorBody::new(provider_not_configured().to_string())),
            )
                .into_response();
        }
    };
    drop(provider_guard);

    let preamble = req
        .preamble
        .as_deref()
        .unwrap_or(state.config.default_preamble.as_str());
    let max_turns = req.max_turns.unwrap_or(state.config.default_max_turns);

    let agent = match provider.build_agent(preamble, &req.context) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody::new(format!("agent build failed: {e}"))),
            )
                .into_response();
        }
    };

    let result = agent
        .prompt(req.prompt.as_str())
        .max_turns(max_turns)
        .extended_details()
        .await;

    match result {
        Ok(resp) => {
            let turns_used = resp.messages.as_ref().map(Vec::len).unwrap_or(1);
            let body = RunResponse {
                response: resp.output,
                turns_used,
                provider: provider.name().to_string(),
                model: provider.model().to_string(),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => {
            // rig wraps the underlying reqwest/rustls error in
            // `CompletionError::HttpError`, whose Display impl drops the
            // source chain. Walk `Error::source()` ourselves so the
            // failing transport-level cause makes it into the log /
            // response body where it can actually be debugged.
            let chain = error_chain(&e);
            warn!(state.log, "agent run failed"; "error" => %e, "chain" => &chain);
            let msg = format!("Agent failed: {e}: {chain}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorBody::new(msg))).into_response()
        }
    }
}
