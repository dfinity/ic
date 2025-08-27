use clap::Parser;
use ic_http_endpoints_async_utils::shutdown_signal;
use ic_logger::{info, new_replica_logger_from_config, warn};
use orchestrator::{args::OrchestratorArgs, orchestrator::Orchestrator};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    let args = OrchestratorArgs::parse();
    let config = args.get_ic_config();
    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.orchestrator_logger);

    let cancellation_token = CancellationToken::new();
    let cancellation_token_clone = cancellation_token.clone();

    let mut orchestrator =
        Orchestrator::new(args, &config, cancellation_token.clone(), logger.clone())
            .await
            .expect("Failed to start orchestrator");
    let mut join_handle =
        tokio::spawn(async move { orchestrator.start_tasks(cancellation_token_clone).await });

    let result = tokio::select! {
        _ = shutdown_signal(logger.clone()) => {
            info!(logger, "Shutting down orchestrator...");
            cancellation_token.cancel();
            join_handle.await
        },
        result = &mut join_handle => {
            result
        },
    };

    match result {
        Err(err) if err.is_panic() => {
            warn!(logger, "Orchestrator panicked: {err}")
        }
        _ => {
            info!(logger, "Orchestrator shut down gracefully")
        }
    }
}
