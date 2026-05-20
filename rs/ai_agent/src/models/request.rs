use serde::Deserialize;

/// Body of `POST /v1/agent/run`.
#[derive(Debug, Deserialize)]
pub struct RunRequest {
    pub prompt: String,
    pub preamble: Option<String>,
    #[serde(default)]
    pub context: Vec<String>,
    /// Tool selection. Three states:
    /// * omitted (`None`) — fall back to the currently-configured default
    ///   (see `POST /v1/tools`; empty out of the box).
    /// * empty list (`Some([])`) — explicitly disable all tools for this
    ///   request.
    /// * non-empty list — wire only the named tools.
    pub tools: Option<Vec<String>>,
    pub max_turns: Option<usize>,
}

/// Body of `POST /v1/agent/chat`.
///
/// The session_id is what makes this multi-turn: omit it on the first
/// call to start a new session (the server returns the freshly-minted
/// id), then echo the same id on every subsequent turn. The server
/// caches the conversation transcript per session id; only the new
/// user prompt needs to be sent each time.
///
/// `preamble`, `tools`, and `max_turns` apply per-request — the agent
/// is rebuilt each turn from the cached transcript, so changing them
/// between turns simply changes how the next turn is run.
#[derive(Debug, Deserialize)]
pub struct ChatRequest {
    pub prompt: String,
    /// Existing session id. If omitted, a new session is created and
    /// the id is returned in the response.
    pub session_id: Option<String>,
    pub preamble: Option<String>,
    /// Tool selection. Same three-state semantics as `RunRequest::tools`.
    pub tools: Option<Vec<String>>,
    pub max_turns: Option<usize>,
}

/// Body of `POST /v1/tools` — replaces the server-wide default tool set
/// used when a request omits its own `tools` field. Pass an empty list
/// to disable tools by default.
#[derive(Debug, Deserialize)]
pub struct ToolsConfigRequest {
    pub tools: Vec<String>,
}
