use std::io::stdout;

use clap::Clap;
use slog::{error, slog_o, Drain, Logger};

use ic_btc_adapter::Adapter;
use ic_btc_adapter::Cli;

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

    match Adapter::new(&config, logger.clone()) {
        Ok(mut adapter) => {
            adapter.run();
        }
        Err(err) => {
            error!(logger, "Error initializing the adapter: {}", err);
        }
    }
}
