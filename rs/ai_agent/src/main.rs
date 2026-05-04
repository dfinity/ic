//! IC AI agent service binary entry point.
//!
//! Starts an Axum server exposing the agent orchestration HTTP API
//! described in `ai-agents-in-nodes-spec.md`. The server is plaintext;
//! a stunnel sidecar terminates TLS for external traffic.

use clap::Parser;
use ic_ai_agent::{config::AppConfig, router::build_router, state::AppState};
use slog::{Drain, Logger, info, o};
use std::{net::SocketAddr, sync::Arc};

#[derive(Debug, Parser)]
#[command(name = "ic-ai-agent", about = "IC AI agent orchestration HTTP API")]
struct Cli {
    /// Address to bind the HTTP server to.
    #[arg(long, env = "IC_AI_AGENT_ADDR", default_value = "127.0.0.1:11501")]
    addr: SocketAddr,
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

    let config = AppConfig::default();
    let state = Arc::new(AppState::new(config, log.clone()));
    let app = build_router(state);

    info!(log, "ic-ai-agent listening"; "addr" => %cli.addr);

    let listener = tokio::net::TcpListener::bind(cli.addr).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
