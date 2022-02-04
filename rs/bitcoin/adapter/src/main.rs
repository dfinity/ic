use clap::Clap;
use ic_btc_adapter::{spawn_adapter, spawn_grpc_server, AdapterRequest, Cli};
use slog::{error, slog_o, Drain, Logger};
use std::io::stdout;
use tokio::{
    sync::oneshot,
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

    let sender = match spawn_adapter(&config, logger.clone()) {
        Ok(sender) => sender,
        Err(err) => {
            error!(logger, "Error initializing the adapter: {}", err);
            return;
        }
    };
    spawn_grpc_server(sender.clone());

    loop {
        let (tx, rx) = oneshot::channel();
        sender
            .send((AdapterRequest::Tick, tx))
            .unwrap_or_else(|_e| error!(logger, "Sending tick request failed."));
        if let Err(_err) = rx.await {
            error!(logger, "Receiving tick response failed.");
        }
        sleep(Duration::from_millis(100)).await;
    }
}
