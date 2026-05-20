use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use slog::{info, warn};

use crate::{
    handlers::tools::read_defaults as read_default_tools,
    models::{ChatRequest, ChatResponse, ErrorBody},
    providers::{AiProvider, provider_not_configured},
    state::AppState,
    tools::validate_tool_names,
};

/// `POST /v1/agent/chat` — multi-turn agent invocation with
/// server-managed transcript.
///
/// Wire shape:
/// * Without `session_id`: the server creates a fresh session with
///   an empty transcript, runs the prompt, and returns the freshly-
///   minted session id alongside the response.
/// * With `session_id`: the server replays the cached transcript
///   into the agent, runs the new prompt, and appends the resulting
///   turn (user message + any tool-call interleavings + assistant
///   reply) back into the cached transcript.
///
/// The agent itself is rebuilt per request — that's cheap (struct
/// construction + tool wiring), and it picks up `POST /v1/config`
/// changes naturally. Per-request `preamble`, `tools`, and
/// `max_turns` always apply.
pub async fn chat(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChatRequest>,
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

    // Resolve the provider once for this request.
    let provider = match read_provider(&state) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };

    // Pull the cached transcript (if any). The snapshot is owned —
    // we never hold the store mutex across the LLM `.await`.
    let (mut history, session_id, is_new) = match req.session_id.as_deref() {
        Some(id) => match state.sessions.get(id) {
            Some(snap) => (snap.history, id.to_string(), false),
            None => {
                // Caller passed an id we don't know (or that has
                // expired). Honour the id by keying the new session
                // under it, rather than minting a different one and
                // leaving the caller's id orphaned.
                (Vec::new(), id.to_string(), true)
            }
        },
        None => (Vec::new(), crate::sessions::SessionStore::fresh_id(), true),
    };

    let preamble = req
        .preamble
        .as_deref()
        .unwrap_or(state.config.default_preamble.as_str());
    let max_turns = req.max_turns.unwrap_or(state.config.default_max_turns);

    // `AiProvider::prompt` matches on the variant internally to construct
    // the right concretely-typed `rig::Agent<M>` and return a unified
    // `ProviderRun { output, new_messages }` (new_messages carries the
    // user prompt + tool-call interleavings + assistant reply, in the
    // order needed to extend the cached transcript).
    let result = provider
        .prompt(
            &state,
            preamble,
            &[],
            &tools,
            req.prompt.as_str(),
            history.clone(),
            max_turns,
        )
        .await;

    match result {
        Ok(run) => {
            // Extend the snapshot with the new turns produced by this
            // request.
            history.extend(run.new_messages.into_iter());

            // Persist the updated transcript. For new sessions this
            // is the first `put`; for existing ones it's an
            // `update_history` (which silently no-ops if the session
            // was evicted while we were `await`ing — see the comment
            // on `SessionStore::update_history`).
            if is_new {
                state.sessions.put(
                    Some(session_id.clone()),
                    history,
                    provider.name(),
                    provider.model().to_string(),
                );
                info!(
                    state.log,
                    "created chat session";
                    "session_id" => &session_id,
                    "provider" => provider.name(),
                    "model" => provider.model()
                );
            } else {
                state.sessions.update_history(&session_id, history);
            }

            let body = ChatResponse {
                response: run.output,
                session_id,
                provider: provider.name().to_string(),
                model: provider.model().to_string(),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => {
            warn!(state.log, "agent chat failed"; "error" => %e, "session_id" => &session_id);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody::new(format!("Agent failed: {e}"))),
            )
                .into_response()
        }
    }
}

/// Read the active provider, returning a 503 response if `/v1/config`
/// hasn't been called yet (or the lock is poisoned, which would mean
/// a previous `/v1/config` write panicked mid-update — best handled
/// the same way as "not configured").
///
/// The error variant is boxed so the resulting `Result` stays small;
/// `axum::response::Response` is ~128 bytes and `clippy::result_large_err`
/// otherwise complains.
fn read_provider(state: &Arc<AppState>) -> Result<AiProvider, Box<axum::response::Response>> {
    let guard = match state.provider.read() {
        Ok(g) => g,
        Err(_) => return Err(Box::new(provider_unavailable())),
    };
    match guard.as_ref() {
        Some(p) => Ok(p.clone()),
        None => Err(Box::new(provider_unavailable())),
    }
}

/// Build the 503 "provider not configured" response.
fn provider_unavailable() -> axum::response::Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorBody::new(provider_not_configured().to_string())),
    )
        .into_response()
}
