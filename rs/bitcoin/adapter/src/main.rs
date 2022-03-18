use clap::Clap;
use ic_btc_adapter::{
    spawn_grpc_server, Adapter, AdapterState, BlockchainManager, Cli, Config, TransactionManager,
};
use ic_logger::{info, new_replica_logger, LoggerImpl, ReplicaLogger};
use serde_json::to_string_pretty;
use slog_async::AsyncGuard;
use std::sync::Arc;
use tokio::{
    sync::Mutex,
    time::{sleep, Duration},
};

pub fn get_logger(config: &Config) -> (ReplicaLogger, AsyncGuard) {
    let base_logger = LoggerImpl::new(&config.logger, "Logger".to_string());
    let logger = new_replica_logger(base_logger.root.clone(), &config.logger);
    (logger, base_logger.async_log_guard)
}

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();
    let config = match cli.get_config() {
        Ok(config) => config,
        Err(err) => {
            panic!("An error occurred while getting the config: {}", err);
        }
    };
    let (logger, _async_log_guard) = get_logger(&config);

    info!(
        logger,
        "Starting the adapter with config: {}",
        to_string_pretty(&config).unwrap()
    );

    let adapter_state = AdapterState::new(config.idle_seconds);
    let blockchain_manager = Arc::new(Mutex::new(BlockchainManager::new(&config, logger.clone())));
    let transaction_manager = Arc::new(Mutex::new(TransactionManager::new(logger.clone())));

    spawn_grpc_server(
        config.clone(),
        adapter_state.clone(),
        blockchain_manager.clone(),
        transaction_manager.clone(),
    );

    let mut adapter = Adapter::new(
        &config,
        logger,
        blockchain_manager,
        transaction_manager,
        adapter_state,
    );
    loop {
        adapter.tick().await;
        sleep(Duration::from_millis(100)).await;
    }
}
