use serde::Serialize;

use super::request::ChatMessage;

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

#[derive(Debug, Serialize)]
pub struct ChatResponse {
    pub response: String,
    pub history: Vec<SerializableChatMessage>,
    pub turns_used: usize,
    pub provider: String,
    pub model: String,
}

#[derive(Debug, Serialize)]
pub struct SerializableChatMessage {
    pub role: String,
    pub content: String,
}

impl From<&ChatMessage> for SerializableChatMessage {
    fn from(m: &ChatMessage) -> Self {
        Self {
            role: match m.role {
                super::request::ChatRole::User => "user".to_string(),
                super::request::ChatRole::Assistant => "assistant".to_string(),
            },
            content: m.content.clone(),
        }
    }
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
