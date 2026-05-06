//! Provider abstraction.
//!
//! Wraps the underlying `rig` provider client behind an enum so new
//! providers can be added without touching handler code: extend
//! [`AiProvider`] with a new variant, add an arm in [`AiProvider::from_request`]
//! and in [`AiProvider::build_agent`], done.

use std::sync::Arc;

use anyhow::anyhow;
use rig::{
    agent::Agent,
    client::CompletionClient,
    providers::gemini::{Client as GeminiClient, completion::CompletionModel as GeminiCompletion},
};
use slog::warn;

use crate::{
    config::ConfigRequest,
    state::AppState,
    tools::{Calculator, CurrentDateTime, IcMetrics, IcState},
};

/// Active AI provider client. Currently Gemini-only; new providers slot in
/// here as additional variants.
#[derive(Clone)]
pub enum AiProvider {
    Gemini { client: GeminiClient, model: String },
}

impl AiProvider {
    /// Build a provider client from a `POST /v1/config` body.
    pub fn from_request(req: &ConfigRequest, default_model: &str) -> anyhow::Result<Self> {
        match req.provider.as_str() {
            "gemini" => {
                if req.api_key.trim().is_empty() {
                    return Err(anyhow!("api_key must not be empty"));
                }
                let client = GeminiClient::new(&req.api_key)
                    .map_err(|e| anyhow!("failed to construct Gemini client: {e}"))?;
                let model = req
                    .model
                    .clone()
                    .unwrap_or_else(|| default_model.to_string());
                Ok(Self::Gemini { client, model })
            }
            other => Err(anyhow!("unknown provider: {other}")),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AiProvider::Gemini { .. } => "gemini",
        }
    }

    pub fn model(&self) -> &str {
        match self {
            AiProvider::Gemini { model, .. } => model.as_str(),
        }
    }

    /// Build a configured agent. Tools and context can be filtered/added by
    /// the caller, but in v1 we always wire all built-in tools so requests
    /// can reference any of them by name.
    ///
    /// Takes `Arc<AppState>` so the IC observability tools (`ic_state`,
    /// `ic_metrics`) can pick up the shared replica config path and
    /// lazily-built node directory. Tools that fail to construct
    /// (typically `ic_state` on a node where `ic.json5` is missing or
    /// unreadable) are skipped with a warning rather than failing the
    /// whole agent build — the other tools may still be useful and we
    /// don't want one bad path to take the agent down.
    ///
    /// `ic_logs` is intentionally not wired up here — it's a TODO,
    /// see `tools/ic_logs.rs`.
    pub async fn build_agent(
        &self,
        state: &Arc<AppState>,
        preamble: &str,
        contexts: &[String],
    ) -> anyhow::Result<Agent<GeminiCompletion>> {
        match self {
            AiProvider::Gemini { client, model } => {
                let mut builder = client.agent(model).preamble(preamble);
                for ctx in contexts {
                    builder = builder.context(ctx);
                }
                let mut builder = builder.tool(Calculator).tool(CurrentDateTime);

                match IcState::new(state.clone()).await {
                    Ok(t) => builder = builder.tool(t),
                    Err(e) => {
                        warn!(
                            state.log,
                            "skipping ic_state tool: {}", e;
                            "ic_config_path" => %state.config.ic_config_path.display()
                        );
                    }
                }

                builder = builder.tool(IcMetrics::new(state.clone()));

                Ok(builder.build())
            }
        }
    }
}

/// Shared error message helper for missing-provider conditions.
pub fn provider_not_configured() -> anyhow::Error {
    anyhow!("provider not configured; POST /v1/config first")
}
