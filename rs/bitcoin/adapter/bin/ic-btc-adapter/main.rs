use clap::Parser;
use ic_adapter_metrics_server::start_metrics_grpc;
use ic_btc_adapter::{IncomingSource, start_server};
use ic_http_endpoints_async_utils::abort_on_panic;
use ic_http_endpoints_async_utils::incoming_from_nth_systemd_socket;
use ic_http_endpoints_async_utils::shutdown_signal;
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
    let config = match cli.get_config() {
        Ok(config) => config,
        Err(err) => {
            panic!("An error occurred while getting the config: {err}");
        }
    };
    let (log, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    info!(
        log,
        "Starting the adapter with config: {}",
        to_string_pretty(&config).unwrap()
    );
    let metrics_registry = MetricsRegistry::global();

    // Metrics server should only be started if we are managed by systemd and receive the
    // metrics socket as FD(4).
    // SAFETY: The process is managed by systemd and is configured to start with at metrics socket.
    // Additionally this function is only called once here.
    // Systemd Socket config: ic-https-outcalls-adapter.socket
    // Systemd Service config: ic-https-outcalls-adapter.service
    if config.incoming_source == IncomingSource::Systemd {
        let stream = unsafe { incoming_from_nth_systemd_socket(2) };
        start_metrics_grpc(metrics_registry.clone(), log.clone(), stream);
    }

    start_server(log.clone(), metrics_registry, config).await;
    shutdown_signal(log).await;
}
