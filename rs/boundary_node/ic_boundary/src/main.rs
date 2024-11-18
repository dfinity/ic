use anyhow::Error;
use clap::Parser;
use tikv_jemallocator::Jemalloc;

use crate::cli::Cli;

mod bouncer;
mod cache;
mod check;
mod cli;
mod core;
mod dns;
mod firewall;
mod geoip;
mod http;
mod log;
mod metrics;
mod persist;
mod rate_limiting;
mod retry;
mod routes;
mod snapshot;
#[cfg(any(test, feature = "bench"))]
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
