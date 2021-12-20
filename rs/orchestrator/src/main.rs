use ic_base_server::shutdown_signal;
use orchestrator::args::OrchestratorArgs;
use orchestrator::orchestrator::Orchestrator;
use structopt::StructOpt;

#[tokio::main]
async fn main() {
    let args = OrchestratorArgs::from_args();
    let mut orchestrator = Orchestrator::start(args)
        .await
        .expect("Failed to start orchestrator");
    orchestrator.spawn_wait_and_restart_replica();
    shutdown_signal(orchestrator.logger.inner_logger.root.clone()).await;
    orchestrator.stop_replica();
}
