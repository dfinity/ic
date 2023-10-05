use anyhow::Error;
use clap::Parser;

use crate::cli::Cli;

mod acme;
mod cache;
mod check;
mod cli;
mod configuration;
mod core;
mod dns;
mod firewall;
mod http;
mod management;
mod metrics;
mod nns;
mod persist;
mod rate_limiting;
mod routes;
mod snapshot;
mod tls_verify;

#[cfg(feature = "tls")]
mod tls;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // This line has to be in `main` not in `core` because (to quote the docs):
    // `Libraries should NOT call set_global_default()! That will cause conflicts when executables try to set them later.`

    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .finish(),
    )?;

    let cli = Cli::parse();
    core::main(cli).await
}
