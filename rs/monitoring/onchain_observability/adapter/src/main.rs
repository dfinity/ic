/// This binary is managed by systemd and added to the replica image.
/// The replica communicates with the HTTP adapter over unix domain sockets.
/// Relevant configuration files:
/// systemd service ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.service
/// systemd socket ic-os/guestos/rootfs/etc/systemd/system/ic-onchain-observability-adapter.socket
use clap::Parser;
use ic_async_utils::abort_on_panic;
use ic_logger::{info, new_replica_logger_from_config};
use ic_onchain_observability_adapter::Cli;
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

    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    info!(
        logger,
        "Starting the onchain observability adapter with config: {}",
        to_string_pretty(&config).unwrap()
    );
}
