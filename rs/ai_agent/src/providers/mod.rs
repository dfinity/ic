//! Provider abstraction.
//!
//! Wraps the underlying `rig` provider clients behind an enum. Each request
//! branches on the variant to construct the concretely-typed `rig::Agent<M>`
//! and run a single prompt. The unified [`ProviderRun`] return type lets
//! handlers stay provider-agnostic.
//!
//! To add a new provider:
//! - extend [`AiProvider`] with a new variant carrying its client + model,
//! - add an arm in [`AiProvider::from_request`],
//! - add an arm in [`AiProvider::prompt`] that builds the agent and runs it.

use std::sync::Arc;

use anyhow::anyhow;
use rig::{
    client::{CompletionClient, Nothing},
    completion::Prompt,
    message::Message,
    providers::{
        gemini::Client as GeminiClient,
        ollama::{Client as OllamaClient, OllamaApiKey},
    },
};
use slog::warn;

use crate::{
    config::{AppConfig, ConfigRequest},
    state::AppState,
    tools::{Calculator, CurrentDateTime, IcMetrics, IcState},
};

use rig::tool::{Tool, ToolDyn};

/// Unified outcome of a single prompt run, regardless of underlying provider.
pub struct ProviderRun {
    /// Final assistant text returned to the caller.
    pub output: String,
    /// New turns produced by this request (user prompt + any tool-call
    /// interleavings + assistant reply), in order. Append to the cached
    /// transcript on the chat path; ignore on the single-turn run path.
    pub new_messages: Vec<Message>,
}

/// Active AI provider client.
#[derive(Clone)]
pub enum AiProvider {
    Gemini {
        client: GeminiClient,
        model: String,
    },
    Ollama {
        client: OllamaClient,
        model: String,
        /// Kept for `/v1/config` echo / diagnostics; the client already
        /// holds the URL internally.
        base_url: String,
    },
}

impl AiProvider {
    /// Build a default `Ollama` provider pointing at the local plaintext
    /// loopback (`127.0.0.1:11435`), which is where the on-node
    /// `ollama.service` listens. This is installed at process startup so
    /// the agent is usable without a prior `/v1/config` call.
    pub fn default_ollama(cfg: &AppConfig) -> anyhow::Result<Self> {
        Self::build_ollama(
            &cfg.default_ollama_base_url,
            None,
            &cfg.default_ollama_model,
        )
    }

    /// Build a provider client from a `POST /v1/config` body.
    pub fn from_request(req: &ConfigRequest, cfg: &AppConfig) -> anyhow::Result<Self> {
        match req.provider.as_str() {
            "gemini" => {
                let api_key = req
                    .api_key
                    .as_deref()
                    .filter(|k| !k.trim().is_empty())
                    .ok_or_else(|| anyhow!("api_key is required for the gemini provider"))?;
                let client = GeminiClient::new(api_key)
                    .map_err(|e| anyhow!("failed to construct Gemini client: {e}"))?;
                let model = req
                    .model
                    .clone()
                    .unwrap_or_else(|| cfg.default_gemini_model.clone());
                Ok(Self::Gemini { client, model })
            }
            "ollama" => {
                let base_url = req
                    .base_url
                    .clone()
                    .unwrap_or_else(|| cfg.default_ollama_base_url.clone());
                let model = req
                    .model
                    .clone()
                    .unwrap_or_else(|| cfg.default_ollama_model.clone());
                Self::build_ollama(&base_url, req.api_key.as_deref(), &model)
            }
            other => Err(anyhow!("unknown provider: {other}")),
        }
    }

    fn build_ollama(base_url: &str, api_key: Option<&str>, model: &str) -> anyhow::Result<Self> {
        // The rig ollama client defaults to `http://localhost:11434`, which
        // on a deployed AiNode is the *TLS* endpoint terminated by stunnel.
        // We always point at the plaintext loopback explicitly to keep this
        // working in-process without TLS.
        let builder = OllamaClient::builder();
        let builder = match api_key.filter(|k| !k.trim().is_empty()) {
            Some(key) => builder.api_key::<OllamaApiKey>(key.to_string()),
            None => builder.api_key::<OllamaApiKey>(Nothing),
        };
        let client = builder
            .base_url(base_url)
            .build()
            .map_err(|e| anyhow!("failed to construct Ollama client: {e}"))?;
        Ok(Self::Ollama {
            client,
            model: model.to_string(),
            base_url: base_url.to_string(),
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            AiProvider::Gemini { .. } => "gemini",
            AiProvider::Ollama { .. } => "ollama",
        }
    }

    pub fn model(&self) -> &str {
        match self {
            AiProvider::Gemini { model, .. } => model.as_str(),
            AiProvider::Ollama { model, .. } => model.as_str(),
        }
    }

    /// Run a single prompt through the active provider, optionally with a
    /// prior transcript (`history`) and a context list. Returns the
    /// assistant text together with the new turns produced by this
    /// request, ready to be appended to the cached transcript.
    pub async fn prompt(
        &self,
        state: &Arc<AppState>,
        preamble: &str,
        contexts: &[String],
        tools: &[String],
        user_prompt: &str,
        history: Vec<Message>,
        max_turns: usize,
    ) -> anyhow::Result<ProviderRun> {
        // The agent type differs per provider (`Agent<M>` is concretely
        // parametric on the completion model), so each arm builds its own
        // agent and runs the prompt. The duplication is small and keeps
        // the call sites free of generics.
        match self {
            AiProvider::Gemini { client, model } => {
                let mut builder = client.agent(model).preamble(preamble);
                for ctx in contexts {
                    builder = builder.context(ctx);
                }
                // Tool wiring is opt-in: only attach the tools named in
                // `tools`. Names are validated upstream by the handler.
                // We collect into a single `Vec<Box<dyn ToolDyn>>` and
                // call `.tools(...)` once (or skip it altogether when
                // empty) because `AgentBuilder` uses a typestate that
                // makes per-tool `if` branches awkward to reassign.
                let tool_objs = collect_tools(state, tools).await;
                let agent = if tool_objs.is_empty() {
                    builder.build()
                } else {
                    builder.tools(tool_objs).build()
                };

                let resp = agent
                    .prompt(user_prompt)
                    .with_history(history)
                    .max_turns(max_turns)
                    .extended_details()
                    .await?;
                Ok(ProviderRun {
                    output: resp.output,
                    new_messages: resp.messages.unwrap_or_default(),
                })
            }
            AiProvider::Ollama { client, model, .. } => {
                let mut builder = client.agent(model).preamble(preamble);
                for ctx in contexts {
                    builder = builder.context(ctx);
                }
                // See the gemini arm above for the rationale behind the
                // collect-then-`.tools(...)` pattern. Tool support
                // across ollama models is patchy (gemma3 small variants
                // in particular reject tool-augmented prompts), which
                // is why the default tool set is empty.
                let tool_objs = collect_tools(state, tools).await;
                let agent = if tool_objs.is_empty() {
                    builder.build()
                } else {
                    builder.tools(tool_objs).build()
                };

                let resp = agent
                    .prompt(user_prompt)
                    .with_history(history)
                    .max_turns(max_turns)
                    .extended_details()
                    .await?;
                Ok(ProviderRun {
                    output: resp.output,
                    new_messages: resp.messages.unwrap_or_default(),
                })
            }
        }
    }
}

/// Build the boxed tool list for a request, given the resolved names.
///
/// Names are validated upstream by the handlers; unknown entries here
/// are silently dropped (defensive — the 400 path catches them first).
/// `IcState` is async-constructed and can legitimately fail on a node
/// where `ic.json5` is missing; we log and skip rather than fail the
/// whole prompt, matching the original behavior.
async fn collect_tools(state: &Arc<AppState>, names: &[String]) -> Vec<Box<dyn ToolDyn>> {
    let mut out: Vec<Box<dyn ToolDyn>> = Vec::new();
    for name in names {
        match name.as_str() {
            n if n == Calculator::NAME => out.push(Box::new(Calculator)),
            n if n == CurrentDateTime::NAME => out.push(Box::new(CurrentDateTime)),
            n if n == IcState::NAME => match IcState::new(state.clone()).await {
                Ok(t) => out.push(Box::new(t)),
                Err(e) => warn!(
                    state.log,
                    "skipping ic_state tool: {}", e;
                    "ic_config_path" => %state.config.ic_config_path.display()
                ),
            },
            n if n == IcMetrics::NAME => out.push(Box::new(IcMetrics::new(state.clone()))),
            _ => {} // unknown name; handler-level validation already rejects these
        }
    }
    out
}

/// Shared error message helper for missing-provider conditions. The default
/// provider is installed at startup, so this should only fire if a
/// `/v1/config` write left the slot empty (it currently never does, but
/// keep the helper for symmetry with the lock-poisoned recovery path).
pub fn provider_not_configured() -> anyhow::Error {
    anyhow!("provider not configured; POST /v1/config first")
}
