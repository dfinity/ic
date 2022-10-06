use clap::{crate_authors, crate_version, Parser};
use futures::try_join;
use tracing::{error, Instrument};

mod canister_id;
mod config;
mod headers;
mod http_client;
mod logging;
mod metrics;
mod proxy;
mod validate;

use crate::{
    metrics::{MetricParams, WithMetrics},
    validate::Validator,
};

#[derive(Parser)]
#[clap(
    version = crate_version!(),
    author = crate_authors!(),
    propagate_version = true,
)]
struct Opts {
    /// The options for logging
    #[clap(flatten)]
    log: logging::Opts,

    /// The options for the HTTP client
    #[clap(flatten)]
    http_client: http_client::Opts,

    /// The options for metrics
    #[clap(flatten)]
    metrics: metrics::Opts,

    /// The options for the canister resolver
    #[clap(flatten)]
    canister_id: canister_id::Opts,

    /// The options for the proxy server
    #[clap(flatten)]
    proxy: proxy::Opts,
}

fn main() -> Result<(), anyhow::Error> {
    let Opts {
        log,
        http_client,
        metrics,
        canister_id,
        proxy,
        ..
    } = Opts::parse();

    let _span = logging::setup(log);

    let client = http_client::setup(http_client)?;

    let (meter, metrics) = metrics::setup(metrics);

    let resolver = canister_id::setup(canister_id)?;

    let validator = Validator::new();
    let validator = WithMetrics(validator, MetricParams::new(&meter, "validator"));

    let proxy = proxy::setup(
        proxy::SetupArgs {
            resolver,
            validator,
            client,
        },
        proxy,
    )?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(10)
        .enable_all()
        .build()?;

    rt.block_on(
        async move {
            let v = try_join!(
                metrics.run().in_current_span(),
                proxy.run().in_current_span(),
            );
            if let Err(v) = v {
                error!("Runtime crashed: {v}");
                return Err(v);
            }
            Ok(())
        }
        .in_current_span(),
    )?;

    Ok(())
}
