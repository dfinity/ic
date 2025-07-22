use clap::Parser;
use ic_http_endpoints_async_utils::shutdown_signal;
use ic_logger::{info, new_replica_logger_from_config, warn};
use orchestrator::{args::OrchestratorArgs, orchestrator::Orchestrator};

#[tokio::main]
async fn main() {
    let args = OrchestratorArgs::parse();
    let config = args.get_ic_config();
    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.orchestrator_logger);

    let (exit_sender, exit_signal) = tokio::sync::watch::channel(false);

    let mut orchestrator = Orchestrator::new(args, &config, logger.clone())
        .await
        .expect("Failed to start orchestrator");
    let join_handle = tokio::spawn(async move { orchestrator.start_tasks(exit_signal).await });
    shutdown_signal(logger.clone()).await;

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
