/// This binary is managed by systemd and added to the replica image.
/// The replica communicates with the HTTP adapter over unix domain sockets.
/// Relevant configuration files:
/// systemd service ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.service
/// systemd socket ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.socket
use clap::Clap;

use ic_async_utils::{ensure_single_systemd_socket, incoming_from_first_systemd_socket};
use ic_canister_http_adapter::CanisterHttp;
use ic_canister_http_adapter::Cli;
use ic_canister_http_adapter_service::http_adapter_server::HttpAdapterServer;
use serde_json::to_string_pretty;
use slog::{error, info, slog_o, Drain, Logger};
use std::io::stdout;
use tonic::transport::Server;

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();
    // TODO: add logs (NET-853)
    let plain = slog_term::PlainSyncDecorator::new(stdout());
    let drain = slog_term::FullFormat::new(plain)
        .build()
        .filter_level(cli.get_logging_level())
        .fuse();
    let logger = Logger::root(drain, slog_o!());

    let config = match cli.get_config() {
        Ok(config) => config,
        Err(err) => {
            error!(
                logger,
                "An error occurred while getting the config:\n {}", err
            );
            return;
        }
    };
    info!(
        logger,
        "Starting the adapter with config: {}",
        to_string_pretty(&config).unwrap()
    );

    // make sure we receive only one socket from systemd
    ensure_single_systemd_socket();

    // Creates an async stream from the socket file descripter passed to this process by systemd (as FD #3).
    // Make sure to only call this function once in this process. Calling it multiple times leads to multiple socket listeners
    let incoming = incoming_from_first_systemd_socket();

    let canister_http = CanisterHttp::new();
    let server = Server::builder()
        .add_service(HttpAdapterServer::new(canister_http))
        .serve_with_incoming(incoming);

    // Run this server for... forever!
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
