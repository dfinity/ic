//! Runtime configuration for the AI agent service.
//!
//! In v1 the only required configuration is the Gemini API key, which is
//! supplied at runtime via `POST /v1/config` rather than via env vars (see
//! the spec). Defaults below cover the rest.

use serde::{Deserialize, Serialize};

/// Default Gemini model used if `/v1/config` doesn't override it.
pub const DEFAULT_GEMINI_MODEL: &str = "gemini-2.0-flash";

/// Default agent system prompt.
pub const DEFAULT_PREAMBLE: &str = "You are a concise, helpful assistant. \
    When tools are provided, prefer using them for any factual, computational, \
    or time-sensitive request.";

/// Default cap on tool-call turns per agent invocation.
pub const DEFAULT_MAX_TURNS: usize = 5;

/// Static configuration baked in at startup. The actual provider client is
/// created later, when `/v1/config` is invoked with the API key.
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub default_model: String,
    pub default_preamble: String,
    pub default_max_turns: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            default_model: DEFAULT_GEMINI_MODEL.to_string(),
            default_preamble: DEFAULT_PREAMBLE.to_string(),
            default_max_turns: DEFAULT_MAX_TURNS,
        }
    }
}

/// Body of `POST /v1/config`. Currently only Gemini is supported.
#[derive(Debug, Deserialize)]
pub struct ConfigRequest {
    /// Provider name. Defaults to `gemini`.
    #[serde(default = "default_provider")]
    pub provider: String,
    /// Provider API key. Required for `gemini`.
    pub api_key: String,
    /// Optional model override.
    pub model: Option<String>,
    /// Optional default preamble override.
    pub preamble: Option<String>,
}

fn default_provider() -> String {
    "gemini".to_string()
}

#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub status: &'static str,
    pub provider: String,
    pub model: String,
}
