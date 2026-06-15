//! IC AI agent service binary entry point.
//!
//! Starts an Axum server exposing the agent orchestration HTTP API
//! described in `ai-agents-in-nodes-spec.md`. The server is plaintext;
//! a stunnel sidecar terminates TLS for external traffic.

use clap::Parser;
use ic_ai_agent::{
    config::{AppConfig, DEFAULT_IC_CONFIG_PATH, DEFAULT_OLLAMA_BASE_URL, DEFAULT_OLLAMA_MODEL},
    providers::AiProvider,
    router::build_router,
    sessions::{DEFAULT_IDLE_TTL, DEFAULT_MAX_SESSIONS},
    state::AppState,
};
use slog::{Drain, Logger, info, o, warn};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

#[derive(Debug, Parser)]
#[command(name = "ic-ai-agent", about = "IC AI agent orchestration HTTP API")]
struct Cli {
    /// Address to bind the HTTP server to.
    #[arg(long, env = "IC_AI_AGENT_ADDR", default_value = "127.0.0.1:11501")]
    addr: SocketAddr,

    /// Path to the replica `ic.json5` config. Used by `ic_state` to find
    /// the on-disk state root, and by `ic_metrics` to find the registry
    /// local store for resolving peer node IPv6 addresses.
    #[arg(long, env = "IC_AI_AGENT_IC_CONFIG", default_value = DEFAULT_IC_CONFIG_PATH)]
    ic_config: PathBuf,

    /// Maximum number of concurrently-cached chat sessions before the
    /// LRU starts evicting.
    #[arg(long, env = "IC_AI_AGENT_MAX_SESSIONS", default_value_t = DEFAULT_MAX_SESSIONS)]
    max_sessions: usize,

    /// Per-session idle TTL in seconds. Sessions untouched for longer
    /// than this are evicted on next access.
    #[arg(long, env = "IC_AI_AGENT_SESSION_IDLE_TTL_SECS", default_value_t = DEFAULT_IDLE_TTL.as_secs())]
    session_idle_ttl_secs: u64,

    /// Default Ollama base URL. Points at the local plaintext loopback
    /// that `ollama.service` binds to on a deployed AiNode.
    #[arg(long, env = "IC_AI_AGENT_OLLAMA_BASE_URL", default_value = DEFAULT_OLLAMA_BASE_URL)]
    ollama_base_url: String,

    /// Default Ollama model. Must match a model pre-pulled into
    /// `/opt/ollama-models` (see `ollama-pull-gemma.sh`) or one
    /// otherwise made available to `ollama.service`.
    #[arg(long, env = "IC_AI_AGENT_OLLAMA_MODEL", default_value = DEFAULT_OLLAMA_MODEL)]
    ollama_model: String,
}

fn make_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    Logger::root(drain, o!("component" => "ic-ai-agent"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let log = make_logger();

    // Install the process-wide rustls crypto provider exactly once.
    //
    // rig 0.36 transitively pulls reqwest 0.13, which we configure with
    // `rustls-no-provider` to avoid linking aws-lc-rs alongside the
    // workspace's existing ring provider (mixing the two crashes rustls
    // 0.23 at startup with `no process-level CryptoProvider available`).
    // The flip side of `rustls-no-provider` is that *no* provider is
    // auto-installed -- so we have to do it ourselves before the first
    // `reqwest::Client::builder().build()` call inside rig. Without
    // this, every Gemini request fails synchronously with the opaque
    // `error sending request for url (...)` you see wrapped by rig as
    // `CompletionError::HttpError`.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = AppConfig {
        ic_config_path: cli.ic_config.clone(),
        max_sessions: cli.max_sessions,
        session_idle_ttl: Duration::from_secs(cli.session_idle_ttl_secs),
        default_ollama_base_url: cli.ollama_base_url.clone(),
        default_ollama_model: cli.ollama_model.clone(),
        ..AppConfig::default()
    };
    let state = Arc::new(AppState::new(config, log.clone()));

    // Pre-install the default Ollama provider so the agent is usable
    // without a prior `/v1/config` call. A failure here only means the
    // initial provider couldn't be constructed (e.g. malformed URL);
    // callers can still install a working provider via `/v1/config`,
    // so we log a warning and continue rather than abort startup.
    match AiProvider::default_ollama(&state.config) {
        Ok(p) => {
            info!(
                log, "default ollama provider installed";
                "model" => p.model(), "base_url" => &cli.ollama_base_url
            );
            match state.provider.write() {
                Ok(mut g) => *g = Some(p),
                Err(poisoned) => *poisoned.into_inner() = Some(p),
            }
        }
        Err(e) => warn!(
            log, "failed to install default ollama provider; \
                  /v1/config will be required before the agent is usable";
            "error" => %e
        ),
    }

    let app = build_router(state);

    info!(log, "ic-ai-agent listening"; "addr" => %cli.addr);

    let listener = tokio::net::TcpListener::bind(cli.addr).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
