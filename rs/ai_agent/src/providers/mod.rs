//! Provider abstraction.
//!
//! Wraps the underlying `rig` provider client behind an enum so new
//! providers can be added without touching handler code: extend
//! [`AiProvider`] with a new variant, add an arm in [`AiProvider::from_request`]
//! and in [`AiProvider::build_agent`], done.

use anyhow::anyhow;
use rig::{
    agent::Agent,
    client::CompletionClient,
    providers::gemini::{Client as GeminiClient, completion::CompletionModel as GeminiCompletion},
};

use crate::{
    config::ConfigRequest,
    tools::{Calculator, CurrentDateTime},
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
    pub fn build_agent(
        &self,
        preamble: &str,
        contexts: &[String],
    ) -> anyhow::Result<Agent<GeminiCompletion>> {
        match self {
            AiProvider::Gemini { client, model } => {
                let mut builder = client.agent(model).preamble(preamble);
                for ctx in contexts {
                    builder = builder.context(ctx);
                }
                let agent = builder.tool(Calculator).tool(CurrentDateTime).build();
                Ok(agent)
            }
        }
    }
}

/// Shared error message helper for missing-provider conditions.
pub fn provider_not_configured() -> anyhow::Error {
    anyhow!("provider not configured; POST /v1/config first")
}
