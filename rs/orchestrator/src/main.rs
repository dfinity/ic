use clap::Parser;
use ic_async_utils::shutdown_signal;
use ic_logger::new_replica_logger_from_config;
use orchestrator::args::OrchestratorArgs;
use orchestrator::firewall::StartupFirewall;
use orchestrator::orchestrator::Orchestrator;

#[tokio::main]
async fn main() {
    let args = OrchestratorArgs::parse();
    let config = args.get_ic_config();
    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.orchestrator_logger);

    // Set up initial firewall before starting orchestrator and its firewalling system.
    // We do this well before attempting to start the orchestrator since we need these
    // basic rules applied before the orchestrator starts.  Importantly, we do not do
    // this in Orchestrator::new() since that would make the new() method change the
    // state of the machine (id est, side effects) before spawn_tasks(), which is the
    // real meat of the orchestrator, has had a chance to start applying side effects.
    let startup_firewall = StartupFirewall::new(config.firewall.clone(), logger.clone());
    startup_firewall.check_and_update().await;

    let mut orchestrator = Orchestrator::new(args, startup_firewall)
        .await
        .expect("Failed to start orchestrator");
    let logger = orchestrator.logger.inner_logger.root.clone();
    orchestrator.spawn_tasks();
    shutdown_signal(logger).await;
    orchestrator.shutdown().await;
}
