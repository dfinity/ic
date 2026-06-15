//! Runtime configuration for the AI agent service.
//!
//! In v1 the only required configuration is the Gemini API key, which is
//! supplied at runtime via `POST /v1/config` rather than via env vars (see
//! the spec). Defaults below cover the rest.

use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

use crate::sessions::{DEFAULT_IDLE_TTL, DEFAULT_MAX_SESSIONS};

/// Default Gemini model used if `/v1/config` doesn't override it.
///
/// `gemini-2.0-flash` was retired for new users; switching to `flash-latest`
/// keeps the agent working without pinning to a specific (and deprecatable)
/// version. Callers can still override per-config via the `model` field.
pub const DEFAULT_GEMINI_MODEL: &str = "gemini-flash-latest";

/// Default Ollama model. Matches the model pre-pulled into
/// `/opt/ollama-models` at GuestOS base-image build time (see
/// `ic-os/guestos/context/ollama-pull-gemma.sh`). Callers can override
/// per-config via the `model` field.
pub const DEFAULT_OLLAMA_MODEL: &str = "gemma3:1b";

/// Default Ollama base URL. Points at the plaintext loopback that
/// `ollama.service` binds to on a deployed AiNode (see
/// `ic-os/components/guestos/ollama/ollama.service`). Public traffic
/// reaches ollama through the stunnel TLS proxy on `:11434`; the agent
/// process talks to the backend directly to skip TLS entirely.
pub const DEFAULT_OLLAMA_BASE_URL: &str = "http://127.0.0.1:11435";

/// Default provider used when the service starts and when `/v1/config`
/// is called without an explicit `provider` field.
pub const DEFAULT_PROVIDER: &str = "ollama";

/// Default agent system prompt.
///
/// IC observability tools (`ic_state`, `ic_metrics`) are described here so
/// the LLM knows to reach for them. Without an explicit mention, the model
/// tends to fall back to "I don't have access to live data" answers instead
/// of using the tools wired into the agent.
///
/// `ic_logs` is intentionally not advertised here — it's a TODO (see
/// `tools/ic_logs.rs`). When it lands, add it back to this prompt with a
/// description of when to prefer it over `ic_metrics`.
pub const DEFAULT_PREAMBLE: &str = "You are a concise, helpful assistant. \
    When tools are provided, prefer using them for any factual, computational, \
    or time-sensitive request. \
    \
    You can also query Internet Computer node observability: `ic_state` for \
    canister/subnet/node metadata read from the locally synced state, and \
    `ic_metrics` for replica/orchestrator/host Prometheus metrics. Prefer \
    `ic_state` for \"what exists\" and `ic_metrics` for \"how is it \
    performing\". Always cite the metric name you used.";

/// Default cap on tool-call turns per agent invocation.
pub const DEFAULT_MAX_TURNS: usize = 5;

/// Default replica config file path on a deployed GuestOS / AiNode. The
/// orchestrator places `ic.json5` here and we re-parse it (with a tmpdir for
/// any path-resolution helpers it does internally) to discover the on-disk
/// state root that the AiNode's state-sync replica writes to **and** the
/// registry local store path used to look up peer node IPv6 addresses.
pub const DEFAULT_IC_CONFIG_PATH: &str = "/run/ic-node/config/ic.json5";

/// Static configuration baked in at startup. The actual provider client is
/// created later, when `/v1/config` is invoked with the API key.
#[derive(Clone, Debug)]
pub struct AppConfig {
    /// Default Gemini model used when `/v1/config` selects gemini without
    /// an explicit `model` field.
    pub default_gemini_model: String,
    /// Default Ollama model used at startup and when `/v1/config` selects
    /// ollama without an explicit `model` field.
    pub default_ollama_model: String,
    /// Default Ollama base URL used at startup and when `/v1/config`
    /// selects ollama without an explicit `base_url` field.
    pub default_ollama_base_url: String,
    pub default_preamble: String,
    pub default_max_turns: usize,
    /// Path to the replica `ic.json5` config. Used by `ic_state` to discover
    /// the on-disk state root, and by `ic_metrics` to discover the
    /// registry local store (so node ids can be resolved to IPv6
    /// addresses of peer nodes in the syncing subnet).
    pub ic_config_path: PathBuf,
    /// Maximum number of concurrently-cached chat sessions. Tuned for
    /// AI-node operator workloads, not for serving end users at scale.
    pub max_sessions: usize,
    /// Per-session idle TTL. A session that hasn't received a turn in
    /// this long is dropped on next access.
    pub session_idle_ttl: Duration,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            default_gemini_model: DEFAULT_GEMINI_MODEL.to_string(),
            default_ollama_model: DEFAULT_OLLAMA_MODEL.to_string(),
            default_ollama_base_url: DEFAULT_OLLAMA_BASE_URL.to_string(),
            default_preamble: DEFAULT_PREAMBLE.to_string(),
            default_max_turns: DEFAULT_MAX_TURNS,
            ic_config_path: PathBuf::from(DEFAULT_IC_CONFIG_PATH),
            max_sessions: DEFAULT_MAX_SESSIONS,
            session_idle_ttl: DEFAULT_IDLE_TTL,
        }
    }
}

/// Body of `POST /v1/config`. Supports `ollama` (default) and `gemini`.
#[derive(Debug, Deserialize)]
pub struct ConfigRequest {
    /// Provider name. Defaults to `ollama`.
    #[serde(default = "default_provider")]
    pub provider: String,
    /// Provider API key. Required for `gemini`; optional for `ollama`
    /// (only needed when talking to a proxied/secured ollama instance).
    #[serde(default)]
    pub api_key: Option<String>,
    /// Optional model override. Defaults depend on the provider; see
    /// `DEFAULT_GEMINI_MODEL` / `DEFAULT_OLLAMA_MODEL`.
    pub model: Option<String>,
    /// Optional ollama base URL override (ignored for other providers).
    /// Defaults to `DEFAULT_OLLAMA_BASE_URL`.
    pub base_url: Option<String>,
    /// Optional default preamble override.
    pub preamble: Option<String>,
}

fn default_provider() -> String {
    DEFAULT_PROVIDER.to_string()
}

#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub status: &'static str,
    pub provider: String,
    pub model: String,
}
