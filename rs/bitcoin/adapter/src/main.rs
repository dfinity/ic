use clap::Clap;
use ic_btc_adapter::{spawn_grpc_server, Adapter, Cli};
use slog::{error, slog_o, Drain, Logger};
use std::io::stdout;
use std::sync::Arc;
use tokio::{
    sync::Mutex,
    time::{sleep, Duration},
};

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();
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
                "An error occurred while getting the config: {}", err
            );
            return;
        }
    };

    let adapter = Arc::new(Mutex::new(Adapter::new(&config, logger.clone())));
    spawn_grpc_server(Arc::clone(&adapter));

    loop {
        adapter.lock().await.tick();
        sleep(Duration::from_millis(100)).await;
    }
}
