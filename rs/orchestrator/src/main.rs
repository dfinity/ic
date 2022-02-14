use ic_async_utils::shutdown_signal;
use orchestrator::args::OrchestratorArgs;
use orchestrator::orchestrator::Orchestrator;
use structopt::StructOpt;

#[tokio::main]
async fn main() {
    let args = OrchestratorArgs::from_args();
    let mut orchestrator = Orchestrator::new(args)
        .await
        .expect("Failed to start orchestrator");
    let logger = orchestrator.logger.inner_logger.root.clone();
    orchestrator.spawn_tasks();
    shutdown_signal(logger).await;
    orchestrator.shutdown().await;
}
