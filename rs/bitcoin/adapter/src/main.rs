use clap::Clap;
use ic_btc_adapter::{spawn_grpc_server, start_router, AdapterState, BlockchainManager, Cli};
use ic_logger::{info, new_replica_logger_from_config};
use serde_json::to_string_pretty;
use std::sync::Arc;
use tokio::sync::{mpsc::unbounded_channel, Mutex};

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

    info!(
        logger,
        "Starting the adapter with config: {}",
        to_string_pretty(&config).unwrap()
    );

    let adapter_state = AdapterState::new(config.idle_seconds);
    let blockchain_manager = Arc::new(Mutex::new(BlockchainManager::new(&config, logger.clone())));

    // TODO: we should NOT have an unbounded channel for buffering TransactionManagerRequests.
    let (transaction_manager_tx, transaction_manager_rx) = unbounded_channel();

    spawn_grpc_server(
        config.clone(),
        adapter_state.clone(),
        blockchain_manager.clone(),
        transaction_manager_tx,
    );

    start_router(
        &config,
        logger,
        blockchain_manager,
        transaction_manager_rx,
        adapter_state,
    )
    .await
    .unwrap();
}
