use clap::Parser;
use ic_async_utils::abort_on_panic;
use ic_async_utils::shutdown_signal;
use ic_btc_adapter::{cli::Cli, start_server};
use ic_logger::new_replica_logger_from_config;
use ic_logger::{info, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use serde_json::to_string_pretty;

#[tokio::main]
pub async fn main() {
    // We abort the whole program with a core dump if a single thread panics.
    // This way we can capture all the context if a critical error
    // happens.
    abort_on_panic();

    let cli = Cli::parse();
    let config = match cli.get_config() {
        Ok(config) => config,
        Err(err) => {
            panic!("An error occurred while getting the config: {}", err);
        }
    };
    let (log, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    info!(
        log,
        "Starting the adapter with config: {}",
        to_string_pretty(&config).unwrap()
    );
    let metrics_registry = MetricsRegistry::global();
    start_server(
        &log,
        &metrics_registry,
        &tokio::runtime::Handle::current(),
        config,
    );
    shutdown_signal(log.inner_logger.root.clone()).await;
}
