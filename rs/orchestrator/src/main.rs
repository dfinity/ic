use clap::Parser;
use ic_async_utils::shutdown_signal;
use orchestrator::args::OrchestratorArgs;
use orchestrator::orchestrator::Orchestrator;

#[tokio::main]
async fn main() {
    let args = OrchestratorArgs::parse();

    if args.node_id {
        Orchestrator::node_id(args);
        return;
    }

    if args.dc_id {
        Orchestrator::dc_id(args);
        return;
    }

    let mut orchestrator = Orchestrator::new(args)
        .await
        .expect("Failed to start orchestrator");
    let logger = orchestrator.logger.inner_logger.root.clone();
    orchestrator.spawn_tasks();
    shutdown_signal(logger).await;
    orchestrator.shutdown().await;
}
