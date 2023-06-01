// TODO: remove
#![allow(unused)]

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_scoped::TokioScope;
use async_trait::async_trait;
use axum::{
    routing::{method_routing::get, post},
    Router,
};
use axum_server::{accept::DefaultAcceptor, Server};
use clap::Parser;
use configuration::{Configure, ServiceConfiguration};
use futures::TryFutureExt;
use ic_registry_client::client::{RegistryClient, RegistryClientImpl};
use ic_registry_local_store::LocalStoreImpl;
use ic_registry_replicator::RegistryReplicator;
use lazy_static::lazy_static;
use nns::Load;
use prometheus::{labels, Registry as MetricsRegistry};
use tokio::sync::Mutex;
use tracing::{error, info};
use url::Url;

use crate::{
    check::Runner as CheckRunner,
    configuration::{Configurator, FirewallConfigurator, TlsConfigurator, WithDeduplication},
    metrics::{MetricParams, WithMetrics},
    nns::Loader,
    snapshot::Runner as SnapshotRunner,
    tls::CustomAcceptor,
};

mod check;
mod configuration;
mod firewall;
mod metrics;
mod nns;
mod persist;
mod routes;
mod snapshot;
mod tls;

const SERVICE_NAME: &str = "ic-boundary";

const SECOND: Duration = Duration::from_secs(1);
const MINUTE: Duration = Duration::from_secs(60);

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

    // Registry Client
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

    // Registry Replicator
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

    // TLS (Ingress) Configurator
    let tls_acceptor = Arc::new(ArcSwapOption::new(None));

    let tls_configurator = TlsConfigurator::new(tls_acceptor.clone());
    let tls_configurator = WithDeduplication::wrap(tls_configurator);
    let tls_configurator = WithMetrics(
        tls_configurator,
        MetricParams::new(SERVICE_NAME, "configure_tls"),
    );

    let tls_acceptor = CustomAcceptor::new(tls_acceptor);

    // Firewall Configuration
    let fw_configurator = FirewallConfigurator {};
    let fw_configurator = WithDeduplication::wrap(fw_configurator);
    let fw_configurator = WithMetrics(
        fw_configurator,
        MetricParams::new(SERVICE_NAME, "configure_firewall"),
    );

    // Service Configurator
    let mut svc_configurator = Configurator {
        tls: Box::new(tls_configurator),
        firewall: Box::new(fw_configurator),
    };

    // Configuration
    let configuration_runner = ConfigurationRunner::new(
        Loader::new(registry_client.clone()), // loader
        svc_configurator,                     // configurator
    );
    let configuration_runner = WithMetrics(
        configuration_runner,
        MetricParams::new(SERVICE_NAME, "run_configuration"),
    );
    let configuration_runner = WithThrottle(configuration_runner, ThrottleParams::new(10 * SECOND));
    let mut configuration_runner = configuration_runner;

    // Server / API
    let routers = (
        Router::new().fallback(routes::redirect_to_https),
        Router::new()
            .route("/api/v2/status", get(routes::status))
            .route("/api/v2/canister/:id/query", post(routes::query))
            .route("/api/v2/canister/:id/call", post(routes::call))
            .route("/api/v2/canister/:id/read_state", post(routes::read_state)),
    );

    // HTTP
    let srvs_http = [Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()]
        .into_iter()
        .map(|ip| {
            Server::bind(SocketAddr::new(ip, 8080))
                .acceptor(DefaultAcceptor)
                .serve(routers.0.clone().into_make_service())
        });

    // HTTPS
    let srvs_https = [Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()]
        .into_iter()
        .map(|ip| {
            Server::bind(SocketAddr::new(ip, 443))
                .acceptor(tls_acceptor.clone())
                .serve(routers.1.clone().into_make_service())
        });

    // Snapshots
    let snapshot_runner = SnapshotRunner::new(&routing_table, registry_client);
    let snapshot_runner = WithMetrics(
        snapshot_runner,
        MetricParams::new(SERVICE_NAME, "run_snapshot"),
    );
    let snapshot_runner = WithThrottle(snapshot_runner, ThrottleParams::new(1 * MINUTE));
    let mut snapshot_runner = snapshot_runner;

    // Checks
    let persister = persist::Persister::new(&ROUTES);

    let check_runner = CheckRunner::new(&routing_table, persister);
    let check_runner = WithMetrics(check_runner, MetricParams::new(SERVICE_NAME, "run_check"));
    let check_runner = WithThrottle(check_runner, ThrottleParams::new(10 * SECOND));
    let mut check_runner = check_runner;

    // Runners
    let runners: Vec<Box<dyn Run>> = vec![
        Box::new(configuration_runner),
        Box::new(snapshot_runner),
        Box::new(check_runner),
    ];

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

        // Servers
        srvs_http.for_each(|srv| {
            s.spawn(srv.map_err(|err| anyhow!("failed to start http server: {:?}", err)))
        });

        srvs_https.for_each(|srv| {
            s.spawn(srv.map_err(|err| anyhow!("failed to start https server: {:?}", err)))
        });

        // Runners
        runners.into_iter().for_each(|mut r| {
            s.spawn(async move {
                loop {
                    let _ = r.run().await;
                }
            });
        });
    });

    Ok(())
}

#[async_trait]
trait Run: Send + Sync {
    async fn run(&mut self) -> Result<(), Error>;
}

#[async_trait]
impl<T: Run> Run for WithMetrics<T> {
    async fn run(&mut self) -> Result<(), Error> {
        let start_time = Instant::now();

        let out = self.0.run().await;

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let MetricParams { action } = &self.1;

        info!(action, status, duration, error = ?out.as_ref().err());

        out
    }
}

struct ThrottleParams {
    throttle_duration: Duration,
    next_time: Option<Instant>,
}

impl ThrottleParams {
    fn new(throttle_duration: Duration) -> Self {
        Self {
            throttle_duration,
            next_time: None,
        }
    }
}

struct WithThrottle<T>(T, ThrottleParams);

#[async_trait]
impl<T: Run> Run for WithThrottle<T> {
    async fn run(&mut self) -> Result<(), Error> {
        let current_time = Instant::now();
        let next_time = self.1.next_time.unwrap_or(current_time);

        if next_time > current_time {
            tokio::time::sleep(next_time - current_time).await;
        }
        self.1.next_time = Some(Instant::now() + self.1.throttle_duration);

        self.0.run().await
    }
}

pub struct ConfigurationRunner<L, C> {
    loader: L,
    configurator: C,
}

impl<L, C> ConfigurationRunner<L, C> {
    pub fn new(loader: L, configurator: C) -> Self {
        Self {
            loader,
            configurator,
        }
    }
}

#[async_trait]
impl<L: Load, C: Configure> Run for ConfigurationRunner<L, C> {
    async fn run(&mut self) -> Result<(), Error> {
        let r = self
            .loader
            .load()
            .await
            .context("failed to load service configuration")?;

        // TLS
        self.configurator
            .configure(&ServiceConfiguration::Tls(r.name))
            .await
            .context("failed to apply tls configuration")?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    /// Remove me when there are real tests
    #[test]
    fn noop_test() {
        assert_eq!(1, 1);
    }
}
