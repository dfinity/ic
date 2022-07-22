/// This binary is managed by systemd and added to the replica image.
/// The replica communicates with the HTTP adapter over unix domain sockets.
/// Relevant configuration files:
/// systemd service ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.service
/// systemd socket ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.socket
use clap::Parser;
use ic_adapter_metrics_server::start_metrics_grpc;
use ic_async_utils::{abort_on_panic, incoming_from_first_systemd_socket, incoming_from_path};
use ic_canister_http_adapter::{AdapterServer, Cli, IncomingSource};
use ic_logger::{error, info, new_replica_logger_from_config};
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

    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    let metrics_registry = MetricsRegistry::global();

    // Metrics server should only be started if we are managed by systemd and receive the
    // metrics socket as FD(4).
    // SAFETY: The process is managed by systemd and is configured to start with at metrics socket.
    // Additionally this function is only called once here.
    // Systemd Socket config: ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.socketi
    // Systemd Service config: ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.service
    if config.incoming_source == IncomingSource::Systemd {
        unsafe {
            start_metrics_grpc(metrics_registry, logger.clone());
        }
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
            // SAFETY: We are manged by systemd that is configured to pass socket as FD(3).
            // Additionally, this is the only call to connnect with the systemd socket and
            // therefore we are sole owner.
            .serve(unsafe { incoming_from_first_systemd_socket() })
            .await
            .map_err(|e| error!(logger, "Canister Http adapter crashed: {}", e))
            .expect("gRPC server crashed"),
    };
}
