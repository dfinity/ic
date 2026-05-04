use serde::Deserialize;

/// Body of `POST /v1/agent/run`.
#[derive(Debug, Deserialize)]
pub struct RunRequest {
    pub prompt: String,
    pub preamble: Option<String>,
    #[serde(default)]
    pub context: Vec<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    pub max_turns: Option<usize>,
}

/// Single message in a chat history.
#[derive(Debug, Clone, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    User,
    Assistant,
}

/// Body of `POST /v1/agent/chat`.
#[derive(Debug, Deserialize)]
pub struct ChatRequest {
    pub prompt: String,
    #[serde(default)]
    pub history: Vec<ChatMessage>,
    pub preamble: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    pub max_turns: Option<usize>,
}
