use clap::Clap;
use ic_btc_adapter::{spawn_grpc_server, Adapter, Cli, Config};
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

    let adapter = Arc::new(Mutex::new(Adapter::new(&config, logger.clone())));
    spawn_grpc_server(config, Arc::clone(&adapter));

    loop {
        adapter.lock().await.tick();
        sleep(Duration::from_millis(100)).await;
    }
}
