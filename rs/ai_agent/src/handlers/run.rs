use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use slog::warn;

use crate::{
    handlers::tools::read_defaults as read_default_tools,
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
    // Resolve the effective tool list: per-request override (including
    // an explicit empty list) wins; otherwise fall back to the
    // server-wide default (`POST /v1/tools`, empty out of the box).
    let tools = req
        .tools
        .clone()
        .unwrap_or_else(|| read_default_tools(&state));
    if let Err(unknown) = validate_tool_names(&tools) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody::new(format!("unknown tool: {unknown}"))),
        )
            .into_response();
    }

    // `state.provider` is a sync RwLock; we never hold it across an
    // `.await`. Clone the active provider out and drop the guard
    // immediately by going out of scope at the end of this block.
    let provider = {
        let provider_guard = match state.provider.read() {
            Ok(g) => g,
            Err(_) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorBody::new(provider_not_configured().to_string())),
                )
                    .into_response();
            }
        };
        match provider_guard.as_ref() {
            Some(p) => p.clone(),
            None => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorBody::new(provider_not_configured().to_string())),
                )
                    .into_response();
            }
        }
    };

    let preamble = req
        .preamble
        .as_deref()
        .unwrap_or(state.config.default_preamble.as_str());
    let max_turns = req.max_turns.unwrap_or(state.config.default_max_turns);

    // `AiProvider::prompt` matches on the variant internally and returns
    // a unified `ProviderRun` regardless of the underlying provider.
    let result = provider
        .prompt(
            &state,
            preamble,
            &req.context,
            &tools,
            req.prompt.as_str(),
            Vec::new(),
            max_turns,
        )
        .await;

    match result {
        Ok(run) => {
            let turns_used = run.new_messages.len().max(1);
            let body = RunResponse {
                response: run.output,
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
            // `anyhow::Error` doesn't impl `std::error::Error` directly;
            // deref it to the inner trait object so we can walk `.source()`.
            let chain = error_chain(e.as_ref());
            warn!(state.log, "agent run failed"; "error" => %e, "chain" => &chain);
            let msg = format!("Agent failed: {e}: {chain}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorBody::new(msg))).into_response()
        }
    }
}
