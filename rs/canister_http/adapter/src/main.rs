/// This binary is managed by systemd and added to the replica image.
/// The replica communicates with the HTTP adapter over unix domain sockets.
/// Relevant configuration files:
/// systemd service ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.service
/// systemd socket ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.socket
use clap::Parser;
use ic_async_utils::{
    abort_on_panic, ensure_single_systemd_socket, incoming_from_first_systemd_socket,
    incoming_from_path,
};
use ic_canister_http_adapter::{AdapterServer, Cli, IncomingSource};
use ic_logger::{error, info, new_replica_logger_from_config};
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

    if config.incoming_source == IncomingSource::Systemd {
        // make sure we receive only one socket from systemd
        ensure_single_systemd_socket();
    }

    info!(
        logger,
        "Starting the adapter with config: {}",
        to_string_pretty(&config).unwrap()
    );

    // Create server with https enforcement.
    let server = AdapterServer::new(config.clone(), logger.clone(), true);
    match config.incoming_source {
        IncomingSource::Path(uds_path) => server
            .serve(incoming_from_path(uds_path))
            .await
            .map_err(|e| error!(logger, "Canister Http adapter crashed: {}", e))
            .expect("gRPC server crashed"),
        IncomingSource::Systemd => server
            .serve(incoming_from_first_systemd_socket())
            .await
            .map_err(|e| error!(logger, "Canister Http adapter crashed: {}", e))
            .expect("gRPC server crashed"),
    };
}
