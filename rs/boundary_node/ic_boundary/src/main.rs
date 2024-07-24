use anyhow::Error;
use clap::Parser;
use jemallocator::Jemalloc;

use ic_boundary_lib::cli::Cli;

#[cfg(feature = "tls")]
mod configuration;
#[cfg(feature = "tls")]
mod tls;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    ic_boundary_lib::log::setup_logging(&cli)?;
    ic_boundary_lib::core::main(cli).await
}
