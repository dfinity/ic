/// This binary is managed by systemd and added to the replica image.
/// The replica communicates with the HTTP adapter over unix domain sockets.
/// Relevant configuration files:
/// systemd service ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.service
/// systemd socket ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.socket
use clap::Parser;
use ic_async_utils::{
    ensure_single_systemd_socket, incoming_from_first_systemd_socket, incoming_from_path,
};
use ic_canister_http_adapter::{CanisterHttp, Cli, IncomingSource};
use ic_canister_http_adapter_service::http_adapter_server::HttpAdapterServer;
use ic_logger::{error, info, new_replica_logger_from_config};
use serde_json::to_string_pretty;
use tonic::transport::Server;

#[tokio::main]
pub async fn main() {
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

    let canister_http = CanisterHttp::new(logger.clone());
    match config.incoming_source {
        IncomingSource::Path(uds_path) => Server::builder()
            .add_service(HttpAdapterServer::new(canister_http))
            .serve_with_incoming(incoming_from_path(uds_path))
            .await
            .map_err(|e| error!(logger, "Canister Http adapter crashed: {}", e))
            .expect("gRPC server crashed"),
        IncomingSource::Systemd => Server::builder()
            .add_service(HttpAdapterServer::new(canister_http))
            .serve_with_incoming(incoming_from_first_systemd_socket())
            .await
            .map_err(|e| error!(logger, "Canister Http adapter crashed: {}", e))
            .expect("gRPC server crashed"),
    };
}
