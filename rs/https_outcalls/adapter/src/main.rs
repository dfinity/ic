/// This binary is managed by systemd and added to the replica image.
/// The replica communicates with the HTTP adapter over unix domain sockets.
/// Relevant configuration files:
/// systemd service ic-https-outcalls-adapter.service
/// systemd socket ic-https-outcalls-adapter.socket
use clap::Parser;
use ic_adapter_metrics_server::start_metrics_grpc;
use ic_http_endpoints_async_utils::{
    abort_on_panic, incoming_from_nth_systemd_socket, shutdown_signal,
};
use ic_https_outcalls_adapter::{IncomingSource, start_server};
use ic_logger::{info, new_replica_logger_from_config};
use ic_metrics::MetricsRegistry;
use serde_json::to_string_pretty;

mod cli;

#[tokio::main]
pub async fn main() {
    // We abort the whole program with a core dump if a single thread panics.
    // This way we can capture all the context if a critical error
    // happens.
    abort_on_panic();

    let cli = cli::Cli::parse();

    let config = cli
        .get_config()
        .expect("An error occurred while getting the config.");
    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);
    let metrics_registry = MetricsRegistry::global();

    // Metrics server should only be started if we are managed by systemd and receive the
    // metrics socket as FD(4).
    // SAFETY: The process is managed by systemd and is configured to start with at metrics socket.
    // Additionally this function is only called once here.
    // Systemd Socket config: ic-https-outcalls-adapter.socketi
    // Systemd Service config: ic-https-outcalls-adapter.service
    if config.incoming_source == IncomingSource::Systemd {
        let stream = unsafe { incoming_from_nth_systemd_socket(2) };
        start_metrics_grpc(metrics_registry.clone(), logger.clone(), stream);
    }

    info!(
        logger,
        "Starting the adapter with config: {}",
        to_string_pretty(&config).unwrap()
    );
    start_server(
        &logger,
        &metrics_registry,
        &tokio::runtime::Handle::current(),
        config,
    );
    shutdown_signal(logger.clone()).await;
}
