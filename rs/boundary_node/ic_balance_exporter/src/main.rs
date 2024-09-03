use std::{
    fs::{self, File},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use axum::{body::Body, handler::Handler, routing::get, Extension, Router};
use candid::{CandidType, Decode, DecoderConfig, Encode, Principal};
use clap::Parser;
use dashmap::DashMap;
use futures::stream::FuturesUnordered;
use hyper::{Request, Response, StatusCode};
use ic_agent::{
    agent::http_transport::reqwest_transport::ReqwestTransport, identity::BasicIdentity, Agent,
};
use mockall::automock;
use opentelemetry::{metrics::MeterProvider, KeyValue};
use opentelemetry_prometheus::exporter;
use opentelemetry_sdk::metrics::MeterProviderBuilder;
use prometheus::{labels, Encoder, Registry, TextEncoder};
use serde::Deserialize;
use tokio::{net::TcpListener, task, time::Instant};
use tracing::info;

mod metrics;
use metrics::{MetricParams, WithMetrics};

#[derive(Parser)]
#[clap(name = "Prober")]
struct Cli {
    #[clap(long, default_value = "wallets.json")]
    wallets_path: PathBuf,

    #[clap(long, default_value = "identity.pem")]
    identity_path: PathBuf,

    #[clap(long)]
    root_key_path: Option<PathBuf>,

    #[clap(long, default_value = "https://ic0.app")]
    replica_endpoint: String,

    #[clap(long, default_value = "1m")]
    scrape_interval: humantime::Duration,

    #[clap(long, default_value = "127.0.0.1:9090")]
    metrics_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("failed to set global subscriber");

    // Metrics
    let service_name = "ic-balance-exporter";

    let registry: Registry = Registry::new_custom(
        None,
        Some(labels! {"service".into() => service_name.into()}),
    )
    .unwrap();
    let exporter = exporter().with_registry(registry.clone()).build()?;
    let provider = MeterProviderBuilder::default()
        .with_reader(exporter)
        .build();
    let meter = provider.meter(service_name);

    let wallet_balances: Arc<DashMap<String, u64>> = Arc::new(DashMap::new());
    let wallet_balances_m = Arc::clone(&wallet_balances);

    meter
        .u64_observable_gauge("wallet_balance")
        .with_callback(move |o| {
            for r in wallet_balances_m.iter() {
                let (wallet, balance) = (r.key(), r.value());
                o.observe(*balance, &[KeyValue::new("wallet", wallet.clone())]);
            }
        })
        .with_description("wallet balance")
        .init();

    let metrics_handler = metrics_handler.layer(Extension(MetricsHandlerArgs { registry }));
    let metrics_router = Router::new().route("/metrics", get(metrics_handler));

    let f = File::open(cli.identity_path).context("failed to open identity file")?;
    let identity = BasicIdentity::from_pem(f).context("failed to create basic identity")?;

    let root_key = cli
        .root_key_path
        .map(fs::read)
        .transpose()
        .context("failed to open root key")?;

    let transport =
        ReqwestTransport::create(cli.replica_endpoint).context("failed to create transport")?;

    let agent = Agent::builder()
        .with_transport(transport)
        .with_identity(identity)
        .build()
        .context("failed to build agent")?;

    if let Some(root_key) = &root_key {
        agent.set_root_key(root_key.clone());
    }

    let loader = ContextLoader::new(cli.wallets_path);
    let loader = WithMetrics(loader, MetricParams::new(&meter, "load"));

    let scraper = Scraper::new(agent);
    let scraper = WithMetrics(scraper, MetricParams::new(&meter, "scrape"));

    let runner = Runner::new(loader, scraper, wallet_balances);
    let runner = WithMetrics(runner, MetricParams::new(&meter, "run"));
    let runner = WithThrottle(runner, ThrottleParams::new(cli.scrape_interval.into()));
    let mut runner = runner;

    info!(
        msg = "Starting ic-balance-exporter",
        metrics_addr = cli.metrics_addr.to_string().as_str(),
    );

    let _ = tokio::try_join!(
        task::spawn(async move {
            loop {
                let _ = runner.run().await;
            }
        }),
        task::spawn(async move {
            let listener = TcpListener::bind(&cli.metrics_addr).await.unwrap();
            axum::serve(listener, metrics_router.into_make_service())
                .await
                .map_err(|err| anyhow!("server failed: {:?}", err))
        })
    )
    .context("service failed to run")?;

    Ok(())
}

#[derive(Clone)]
struct MetricsHandlerArgs {
    registry: Registry,
}

async fn metrics_handler(
    Extension(MetricsHandlerArgs { registry }): Extension<MetricsHandlerArgs>,
    _: Request<Body>,
) -> Response<Body> {
    let metric_families = registry.gather();

    let encoder = TextEncoder::new();

    let mut metrics_text = Vec::new();
    if encoder.encode(&metric_families, &mut metrics_text).is_err() {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("Internal Server Error".into())
            .unwrap();
    };

    Response::builder()
        .status(200)
        .body(metrics_text.into())
        .unwrap()
}

#[derive(PartialEq, Debug, Deserialize)]
struct ServiceContext {
    wallets: Vec<String>,
}

#[automock]
#[async_trait]
trait Load: Sync + Send {
    async fn load(&self) -> Result<ServiceContext, Error>;
}

struct ContextLoader {
    wallets_path: PathBuf,
}

impl ContextLoader {
    fn new(wallets_path: PathBuf) -> Self {
        Self { wallets_path }
    }
}

#[async_trait]
impl Load for ContextLoader {
    async fn load(&self) -> Result<ServiceContext, Error> {
        // Wallets
        let f = File::open(&self.wallets_path)
            .with_context(|| format!("failed to open file {}", &self.wallets_path.display()))?;

        let ctx: ServiceContext = serde_json::from_reader(f).context("failed to parse json")?;
        Ok(ctx)
    }
}

#[automock]
#[async_trait]
trait Scrape: Sync + Send {
    async fn scrape(&self, wallet: &Principal) -> Result<u64, Error>;
}

struct Scraper(Arc<Agent>);

impl Scraper {
    fn new(agent: Agent) -> Self {
        Self(Arc::new(agent))
    }
}

#[async_trait]
impl Scrape for Scraper {
    async fn scrape(&self, wallet: &Principal) -> Result<u64, Error> {
        let agent = Arc::clone(&self.0);
        let arg = candid::Encode!()?;
        let result = agent
            .query(wallet, "wallet_balance")
            .with_arg(arg)
            .call()
            .await
            .context("failed to query canister")?;

        // Limit the amount of work for skipping unneeded data on the wire when parsing Candid.
        // The value of 10_000 follows the Candid recommendation.
        const DEFAULT_SKIPPING_QUOTA: usize = 10_000;
        let mut config = DecoderConfig::new();
        config.set_skipping_quota(DEFAULT_SKIPPING_QUOTA);
        config.set_full_error_message(false);

        let Amount { amount } =
            candid::Decode!([config]; &result, Amount).context("failed to decode result")?;

        Ok(amount)
    }
}

#[derive(CandidType, candid::Deserialize)]
struct Amount {
    amount: u64,
}

#[async_trait]
trait Run: Sync + Send {
    async fn run(&mut self) -> Result<(), Error>;
}

struct Runner<L, S> {
    loader: L,
    scraper: Arc<S>,
    wallet_balances: Arc<DashMap<String, u64>>,
}

impl<L, S> Runner<L, S> {
    fn new(loader: L, scraper: S, wallet_balances: Arc<DashMap<String, u64>>) -> Self {
        Self {
            loader,
            scraper: Arc::new(scraper),
            wallet_balances,
        }
    }
}

#[async_trait]
impl<L: 'static + Load, S: 'static + Scrape> Run for Runner<L, S> {
    async fn run(&mut self) -> Result<(), Error> {
        let ServiceContext { wallets } = self
            .loader
            .load()
            .await
            .context("failed to load service context")?;

        let futs = FuturesUnordered::new();

        for wallet in wallets.iter() {
            let scraper = Arc::clone(&self.scraper);
            let wallet_balances = Arc::clone(&self.wallet_balances);

            let wallet = Principal::from_text(wallet).context("failed to parse principal")?;

            futs.push(task::spawn(async move {
                let amount = scraper
                    .scrape(&wallet)
                    .await
                    .context("failed to scrape wallet")?;

                wallet_balances.insert(wallet.to_string(), amount);

                let ret: Result<(), Error> = Ok(());
                ret
            }));
        }

        for fut in futs {
            let _ = fut.await?;
        }

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    use mockall::predicate;
    use std::{collections::HashMap, hash::Hash};

    #[tokio::test]
    async fn it_loads() -> Result<(), Error> {
        use indoc::indoc;
        use std::fs::File;
        use std::io::Write;
        use tempfile::tempdir;

        // Create wallets file
        let wallets_dir = tempdir()?;

        let file_path = wallets_dir.path().join("wallets.json");
        let mut file = File::create(file_path)?;
        writeln!(
            file,
            "{}",
            indoc! {r#"{
                "wallets": [
                    "wallet-1",
                    "wallet-2",
                    "wallet-3"
                ]
            }"#}
        )?;

        // Create loader
        let loader = ContextLoader::new(wallets_dir.path().join("wallets.json"));

        let out = loader.load().await?;
        assert_eq!(
            out,
            ServiceContext {
                wallets: vec![
                    String::from("wallet-1"),
                    String::from("wallet-2"),
                    String::from("wallet-3")
                ]
            }
        );

        Ok(())
    }

    #[tokio::test]
    async fn it_runs() -> Result<(), Error> {
        let mut loader = MockLoad::new();
        loader.expect_load().times(1).returning(|| {
            Ok(ServiceContext {
                wallets: vec![String::from("rwlgt-iiaaa-aaaaa-aaaaa-cai")],
            })
        });

        let mut scraper = MockScrape::new();
        scraper
            .expect_scrape()
            .times(1)
            .with(
                predicate::eq(Principal::from_text(String::from(
                    "rwlgt-iiaaa-aaaaa-aaaaa-cai",
                ))?), // wallet
            )
            .returning(|_| Ok(1));

        let wallet_balances: Arc<DashMap<String, u64>> = Arc::new(DashMap::new());
        let wallet_balances_m = Arc::clone(&wallet_balances);

        let mut runner = Runner::new(
            loader,          // loader
            scraper,         // scraper
            wallet_balances, // wallet_balances
        );

        runner.run().await?;

        let expected_wallet_balances = Arc::new(DashMap::new());
        expected_wallet_balances.insert(String::from("rwlgt-iiaaa-aaaaa-aaaaa-cai"), 1);

        fn to_hashmap<K: Eq + Hash + Clone, V: Clone>(m: Arc<DashMap<K, V>>) -> HashMap<K, V> {
            let mut out = HashMap::new();

            m.iter().for_each(|r| {
                out.insert(
                    r.key().clone(),   // k
                    r.value().clone(), // v
                );
            });

            out
        }

        assert_eq!(
            to_hashmap(wallet_balances_m),
            to_hashmap(expected_wallet_balances),
        );

        Ok(())
    }
}
