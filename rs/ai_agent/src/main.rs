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

    let config = AppConfig::default();
    let state = Arc::new(AppState::new(config, log.clone()));
    let app = build_router(state);

    info!(log, "ic-ai-agent listening"; "addr" => %cli.addr);

    let listener = tokio::net::TcpListener::bind(cli.addr).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}
