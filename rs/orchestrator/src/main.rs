use clap::Parser;
use ic_http_endpoints_async_utils::shutdown_signal;
use ic_logger::{info, warn};
use orchestrator::{args::OrchestratorArgs, orchestrator::Orchestrator};

#[tokio::main]
async fn main() {
    let args = OrchestratorArgs::parse();

    let (exit_sender, exit_signal) = tokio::sync::watch::channel(false);

    let orchestrator = Orchestrator::new(args)
        .await
        .expect("Failed to start orchestrator");
    let logger = orchestrator.logger.clone();
    let join_handle = tokio::spawn(orchestrator.start_tasks(exit_signal));
    shutdown_signal(logger.inner_logger.root.clone()).await;

    exit_sender.send(true).expect("Failed to send exit signal");

    info!(logger, "Shutting down orchestrator...");
    match join_handle.await {
        Err(err) if err.is_panic() => {
            warn!(logger, "Orchestrator panicked: {err}")
        }
        _ => {
            info!(logger, "Orchestrator shut down gracefully")
        }
    }
}
