use anyhow::Error;
use clap::Parser;
use jemallocator::Jemalloc;

use crate::cli::Cli;

mod acme;
mod cache;
mod check;
mod cli;
mod core;
mod dns;
mod firewall;
mod http;
mod management;
mod metrics;
mod persist;
mod rate_limiting;
mod retry;
mod routes;
mod snapshot;
mod tls_verify;

#[cfg(feature = "tls")]
mod configuration;
#[cfg(feature = "tls")]
mod tls;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // This line has to be in `main` not in `core` because (to quote the docs):
    // `Libraries should NOT call set_global_default()! That will cause conflicts when executables try to set them later.`

    let cli = Cli::parse();

    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .with_max_level(cli.monitoring.max_logging_level)
            .json()
            .flatten_event(true)
            .finish(),
    )?;

    core::main(cli).await
}
