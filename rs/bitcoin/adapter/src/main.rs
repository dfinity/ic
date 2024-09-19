use clap::Parser;
use ic_async_utils::abort_on_panic;
use ic_btc_adapter::{cli::Cli, start_grpc_server_and_router};

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

    start_grpc_server_and_router(&config).await;
}
