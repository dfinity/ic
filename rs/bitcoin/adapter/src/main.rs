use clap::Parser;
use ic_adapter_metrics_server::start_metrics_grpc;
use ic_async_utils::{abort_on_panic, shutdown_signal};
use ic_btc_adapter::{
    cli::Cli, config::IncomingSource, spawn_grpc_server, start_router, AdapterState,
    BlockchainState, GetSuccessorsHandler,
};
use ic_logger::{info, new_replica_logger_from_config};
use ic_metrics::MetricsRegistry;
use serde_json::to_string_pretty;
use std::sync::Arc;
use tokio::sync::{mpsc::channel, Mutex};

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
        "Starting the adapter with config: {}",
        to_string_pretty(&config).unwrap()
    );

    let metrics_registry = MetricsRegistry::global();

    // Metrics server should only be started if we are managed by systemd and receive the
    // metrics socket as FD(4).
    // SAFETY: The process is managed by systemd and is configured to start with at metrics socket.
    // Additionally this function is only called once here.
    // Systemd Socket config: ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.socket
    // Systemd Service config: ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.service
    if config.incoming_source == IncomingSource::Systemd {
        unsafe {
            start_metrics_grpc(metrics_registry, logger.clone());
        }
    }

    // TODO: establish what the buffer size should be
    let (blockchain_manager_tx, blockchain_manager_rx) = channel(10);

    let adapter_state = AdapterState::new(config.idle_seconds);
    let blockchain_state = Arc::new(Mutex::new(BlockchainState::new(&config)));
    let get_successors_handler =
        GetSuccessorsHandler::new(&config, blockchain_state.clone(), blockchain_manager_tx);

    // TODO: we should NOT have an unbounded channel for buffering TransactionManagerRequests.
    let (transaction_manager_tx, transaction_manager_rx) = channel(10);

    spawn_grpc_server(
        config.clone(),
        logger.clone(),
        adapter_state.clone(),
        get_successors_handler,
        transaction_manager_tx,
    );

    start_router(
        &config,
        logger.clone(),
        blockchain_state,
        transaction_manager_rx,
        adapter_state,
        blockchain_manager_rx,
    );
    shutdown_signal(logger.inner_logger.root.clone()).await;
}
