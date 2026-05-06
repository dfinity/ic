use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub provider: Option<String>,
    pub model: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RunResponse {
    pub response: String,
    pub turns_used: usize,
    pub provider: String,
    pub model: String,
}

/// Body of a successful `POST /v1/agent/chat` response.
///
/// `session_id` is always present — either echoed back or freshly
/// minted on first turn. Clients should persist it and pass it on
/// every subsequent turn.
#[derive(Debug, Serialize)]
pub struct ChatResponse {
    pub response: String,
    pub session_id: String,
    pub provider: String,
    pub model: String,
}

/// Body of `DELETE /v1/agent/sessions` and
/// `DELETE /v1/agent/sessions/:id`.
#[derive(Debug, Serialize)]
pub struct ClearResponse {
    /// "ok" on success.
    pub status: &'static str,
    /// How many sessions were dropped (0 or 1 for single-session
    /// delete; 0..=N for the bulk delete).
    pub cleared: usize,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
}

impl ErrorBody {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { error: msg.into() }
    }
}
