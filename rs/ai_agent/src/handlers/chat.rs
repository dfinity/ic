use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use rig::completion::{Prompt, message::Message};
use slog::warn;

use crate::{
    models::{
        ChatMessage, ChatRequest, ChatResponse, ErrorBody, request::ChatRole,
        response::SerializableChatMessage,
    },
    providers::provider_not_configured,
    state::AppState,
    tools::validate_tool_names,
};

/// `POST /v1/agent/chat` — multi-turn agent invocation, with caller-managed
/// history. The server appends the new exchange to `history` and returns the
/// updated transcript.
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

    let agent = match provider.build_agent(preamble, &[]) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody::new(format!("agent build failed: {e}"))),
            )
                .into_response();
        }
    };

    let history_msgs: Vec<Message> = req.history.iter().map(to_rig_message).collect();

    let result = agent
        .prompt(req.prompt.as_str())
        .with_history(history_msgs)
        .max_turns(max_turns)
        .extended_details()
        .await;

    match result {
        Ok(resp) => {
            let turns_used = resp.messages.as_ref().map(Vec::len).unwrap_or(1);
            let mut full_history: Vec<SerializableChatMessage> = req
                .history
                .iter()
                .map(SerializableChatMessage::from)
                .collect();
            full_history.push(SerializableChatMessage::from(&ChatMessage {
                role: ChatRole::User,
                content: req.prompt.clone(),
            }));
            full_history.push(SerializableChatMessage::from(&ChatMessage {
                role: ChatRole::Assistant,
                content: resp.output.clone(),
            }));
            let body = ChatResponse {
                response: resp.output,
                history: full_history,
                turns_used,
                provider: provider.name().to_string(),
                model: provider.model().to_string(),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => {
            warn!(state.log, "agent chat failed"; "error" => %e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody::new(format!("Agent failed: {e}"))),
            )
                .into_response()
        }
    }
}

fn to_rig_message(m: &ChatMessage) -> Message {
    match m.role {
        ChatRole::User => Message::user(m.content.clone()),
        ChatRole::Assistant => Message::assistant(m.content.clone()),
    }
}
