use anyhow::Error;
use clap::Parser;
use tikv_jemallocator::Jemalloc;

use crate::cli::Cli;

mod bouncer;
mod check;
mod cli;
mod core;
mod dns;
mod errors;
mod http;
mod log;
mod metrics;
mod persist;
mod rate_limiting;
mod routes;
mod salt_fetcher;
mod snapshot;
#[cfg(test)]
pub mod test_utils;
mod tls_verify;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    log::setup_logging(&cli)?;
    core::main(cli).await
}
