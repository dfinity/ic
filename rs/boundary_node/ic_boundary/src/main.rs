// TODO: remove
#![allow(unused)]

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_scoped::TokioScope;
use async_trait::async_trait;
use axum::{routing::method_routing::get, Router};
use clap::Parser;
use futures::TryFutureExt;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::LocalStoreImpl;
use ic_registry_replicator::RegistryReplicator;
use lazy_static::lazy_static;
use prometheus::{labels, Registry as MetricsRegistry};
use tracing::{error, info};
use url::Url;

mod check;
mod metrics;
mod persist;
mod snapshot;

const SERVICE_NAME: &str = "ic-boundary";

#[derive(Parser)]
#[clap(name = SERVICE_NAME)]
#[clap(author = "Boundary Node Team <boundary-nodes@dfinity.org>")]
struct Cli {
    /// Comma separated list of NNS URLs to bootstrap the registry
    #[clap(long, value_delimiter = ',', default_value = "https://ic0.app")]
    pub nns_urls: Vec<Url>,

    /// The path to the NNS public key file
    #[clap(long)]
    pub nns_pub_key_pem: PathBuf,

    /// The delay between NNS polls in milliseconds
    #[clap(long, default_value = "5000")]
    pub nns_poll_interval_ms: u64,

    /// The registry local store path to be populated
    #[clap(long)]
    pub local_store_path: PathBuf,

    /// Minimum registry version snapshot to process
    #[clap(long, default_value = "0")]
    min_registry_version: u64,

    /// Minimum required OK health checks
    /// for a replica to be included in the routing table
    #[clap(long, default_value = "1")]
    min_ok_count: u8,

    /// Maximum block height lag for a replica to be included in the routing table
    #[clap(long, default_value = "1000")]
    max_height_lag: u64,

    /// The path to the nftables replica ruleset file to update
    #[clap(long, default_value = "/tmp/system_replicas.ruleset")]
    nftables_system_replicas_path: PathBuf,

    /// The name of the nftables variable to export
    #[clap(long, default_value = "system_replica_ips")]
    nftables_system_replicas_var: String,

    /// The socket used to export metrics.
    #[clap(long, default_value = "127.0.0.1:9090")]
    metrics_addr: SocketAddr,
}

lazy_static! {
    static ref METRICS: MetricsRegistry = MetricsRegistry::new_custom(
        None,
        Some(labels! {"service".into() => SERVICE_NAME.into()})
    )
    .unwrap();
}

static ROUTES: ArcSwapOption<persist::Routes> = ArcSwapOption::const_empty();

#[async_trait]
trait Run: Send + Sync {
    async fn run(&mut self) -> Result<(), Error>;
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .finish(),
    )
    .expect("failed to set global subscriber");

    let metrics = &*METRICS;

    let routing_table = ArcSwapOption::const_empty();

    info!(
        msg = format!("Starting {SERVICE_NAME}"),
        metrics_addr = cli.metrics_addr.to_string().as_str(),
    );

    let local_store = Arc::new(LocalStoreImpl::new(&cli.local_store_path));

    let registry_client = Arc::new(RegistryClientImpl::new(
        local_store.clone(), // data_provider
        None,                // metrics_registry
    ));

    registry_client
        .fetch_and_start_polling()
        .context("failed to start registry client")?;

    let nns_pub_key =
        ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key(&cli.nns_pub_key_pem)
            .context("failed to parse nns public key")?;

    let registry_replicator = {
        // Notice no-op logger
        let logger = ic_logger::new_replica_logger(
            slog::Logger::root(slog::Discard, slog::o!()), // logger
            &ic_config::logger::Config::default(),         // config
        );

        RegistryReplicator::new_with_clients(
            logger,
            local_store,
            registry_client.clone(), // registry_client
            Duration::from_millis(cli.nns_poll_interval_ms), // poll_delay
        )
    };

    let snapshot_runner = snapshot::Runner::new(&routing_table, registry_client);
    let persister = persist::Persister::new(&ROUTES);
    let check_runner = check::Runner::new(&routing_table, persister);
    let _ = ROUTES;

    TokioScope::scope_and_block(|s| {
        let metrics_handler = || metrics::handler(metrics);
        let metrics_router = Router::new().route("/metrics", get(metrics_handler));
        s.spawn(
            axum::Server::bind(&cli.metrics_addr)
                .serve(metrics_router.into_make_service())
                .map_err(|err| anyhow!("server failed: {:?}", err)),
        );

        s.spawn(async move {
            registry_replicator
                .start_polling(cli.nns_urls, Some(nns_pub_key))
                .await
                .context("failed to start registry replicator")?
                .await
                .context("registry replicator failed")?;

            Ok(())
        });

        s.spawn(async move {
            let mut snapshot_runner = snapshot_runner;
            loop {
                if let Err(error) = snapshot_runner.run().await {
                    error!(?error, "snapshot_runner failed");
                }
            }
        });

        s.spawn(async move {
            let mut check_runner = check_runner;
            loop {
                if let Err(error) = check_runner.run().await {
                    error!(?error, "check_runner failed");
                }
            }
        });

        // TODO(BOUN-726): Setup axum server for api calls
        // TODO(BOUN-727): Setup route for non-status calls
        // TODO(BOUN-728): Setup route for status calls
    });

    Ok(())
}

#[cfg(test)]
mod test {
    /// Remove me when there are real tests
    #[test]
    fn noop_test() {
        assert_eq!(1, 1);
    }
}
