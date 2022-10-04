use std::{
    fs::File,
    io::BufWriter,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Error};
use async_trait::async_trait;
use axum::{
    body::Body,
    handler::Handler,
    http::{Request, Response, StatusCode},
    routing::get,
    Extension, Router,
};
use bytes::Buf;
use clap::Parser;
use dashmap::DashSet;
use futures::{future::TryFutureExt, stream::FuturesUnordered};
use ic_types::messages::{HttpStatusResponse, ReplicaHealthStatus};
use opentelemetry::{baggage::BaggageExt, global, sdk::Resource, trace::FutureExt, KeyValue};
use opentelemetry_prometheus::PrometheusExporter;
use prometheus::{Encoder, TextEncoder};
use registry::{RoutingTable, Subnet};
use tokio::{sync::Semaphore, task};
use tracing::info;

mod metrics;
mod registry;
mod retry;

use crate::{
    metrics::{MetricParams, WithMetrics},
    registry::{
        CreateRegistryClient, CreateRegistryClientImpl, Snapshot, Snapshotter, WithMinimumVersion,
    },
    retry::WithRetry,
};

const SERVICE_NAME: &str = "control-plane";

const SECOND: Duration = Duration::from_secs(1);
const MINUTE: Duration = Duration::from_secs(60);

#[derive(Parser)]
#[clap(name = SERVICE_NAME)]
#[clap(author = "Boundary Node Team <boundary-nodes@dfinity.org>")]
struct Cli {
    #[clap(long, default_value = "/tmp/store")]
    local_store: PathBuf,

    #[clap(long, default_value = "0")]
    min_registry_version: u64,

    #[clap(long, default_value = "/tmp/routes")]
    routes_dir: PathBuf,

    #[clap(long, default_value = "127.0.0.1:9090")]
    metrics_addr: SocketAddr,
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

    let exporter = opentelemetry_prometheus::exporter()
        .with_resource(Resource::new(vec![KeyValue::new("service", SERVICE_NAME)]))
        .init();

    let meter = global::meter(SERVICE_NAME);

    let metrics_handler = metrics_handler.layer(Extension(MetricsHandlerArgs { exporter }));
    let metrics_router = Router::new().route("/metrics", get(metrics_handler));

    let routing_table: Arc<Mutex<Option<RoutingTable>>> = Arc::new(Mutex::new(None));

    let http_client = reqwest::Client::builder().timeout(10 * SECOND).build()?;

    let local_store = Arc::new(ic_registry_local_store::LocalStoreImpl::new(
        cli.local_store,
    ));

    let create_registry_client = CreateRegistryClientImpl::new(local_store);
    let create_registry_client = WithMetrics(
        create_registry_client,
        MetricParams::new(&meter, SERVICE_NAME, "create_registry_client"),
    );
    let create_registry_client = WithRetry(
        create_registry_client,
        10,         // max_attempts
        1 * SECOND, // attempt_interval
    );
    let mut create_registry_client = create_registry_client;

    let registry_client = create_registry_client
        .create_registry_client()
        .await
        .context("failed to create registry client")?;

    let snapshotter = Snapshotter::new(registry_client);
    let snapshotter = WithMinimumVersion(snapshotter, cli.min_registry_version);
    let snapshotter = WithMetrics(
        snapshotter,
        MetricParams::new(&meter, SERVICE_NAME, "snapshot"),
    );

    let snapshot_runner = SnapshotRunner::new(snapshotter, Arc::clone(&routing_table));
    let snapshot_runner = WithMetrics(
        snapshot_runner,
        MetricParams::new(&meter, SERVICE_NAME, "run"),
    );
    let snapshot_runner = WithThrottle(snapshot_runner, ThrottleParams::new(1 * MINUTE));
    let mut snapshot_runner = snapshot_runner;

    let checker = Checker::new(http_client);
    let checker = WithMetrics(checker, MetricParams::new(&meter, SERVICE_NAME, "check"));
    let checker = WithRetry(
        checker,
        3,          // max_attempts
        1 * SECOND, // attempt_interval
    );
    let checker = WithSemaphore::wrap(checker, 32);

    let persister = Persister::new(cli.routes_dir.clone());
    let persister = WithDedup(persister, None);
    let persister = WithMetrics(
        persister,
        MetricParams::new(&meter, SERVICE_NAME, "persist"),
    );

    let check_persist_runner =
        CheckPersistRunner::new(Arc::clone(&routing_table), checker, persister);
    let check_persist_runner = WithMetrics(
        check_persist_runner,
        MetricParams::new(&meter, SERVICE_NAME, "run"),
    );
    let check_persist_runner = WithThrottle(check_persist_runner, ThrottleParams::new(10 * SECOND));
    let mut check_persist_runner = check_persist_runner;

    info!(
        msg = format!("starting {SERVICE_NAME}").as_str(),
        routes_dir = cli.routes_dir.display().to_string().as_str(),
        metrics_addr = cli.metrics_addr.to_string().as_str(),
    );

    let _ = tokio::try_join!(
        task::spawn(async move {
            loop {
                let _ = snapshot_runner.run().await;
            }
        }),
        task::spawn(async move {
            loop {
                let _ = check_persist_runner.run().await;
            }
        }),
        task::spawn(
            axum::Server::bind(&cli.metrics_addr)
                .serve(metrics_router.into_make_service())
                .map_err(|err| anyhow!("server failed: {:?}", err))
        )
    )
    .context(format!("{SERVICE_NAME} failed to run"))?;

    Ok(())
}

#[derive(Clone)]
struct MetricsHandlerArgs {
    exporter: PrometheusExporter,
}

async fn metrics_handler(
    Extension(MetricsHandlerArgs { exporter }): Extension<MetricsHandlerArgs>,
    _: Request<Body>,
) -> Response<Body> {
    let metric_families = exporter.registry().gather();

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

#[async_trait]
trait Check: 'static + Send + Sync {
    async fn check(&self, addr: &str) -> Result<(), Error>;
}

struct Checker {
    http_client: reqwest::Client,
}

impl Checker {
    fn new(http_client: reqwest::Client) -> Self {
        Self { http_client }
    }
}

#[async_trait]
impl Check for Checker {
    async fn check(&self, addr: &str) -> Result<(), Error> {
        let request = self
            .http_client
            .request(reqwest::Method::GET, format!("http://{addr}/api/v2/status"))
            .build()
            .context("failed to build request")?;

        let response = self
            .http_client
            .execute(request)
            .await
            .context("request failed")?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(anyhow!("request failed with status {}", response.status()));
        }

        let response_reader = response
            .bytes()
            .await
            .context("failed to get response bytes")?
            .reader();

        let HttpStatusResponse {
            replica_health_status,
            ..
        } = serde_cbor::from_reader(response_reader).context("failed to parse cbor response")?;

        if replica_health_status != Some(ReplicaHealthStatus::Healthy) {
            return Err(anyhow!("replica reported unhealthy status"));
        }

        Ok(())
    }
}

enum PersistStatus {
    Completed,
    Skipped,
}

#[async_trait]
trait Persist: Send + Sync {
    async fn persist(&mut self, rt: RoutingTable) -> Result<PersistStatus, Error>;
}

struct Persister {
    routes_dir: PathBuf,
}

impl Persister {
    fn new(routes_dir: PathBuf) -> Self {
        Self { routes_dir }
    }
}

#[async_trait]
impl Persist for Persister {
    async fn persist(&mut self, rt: RoutingTable) -> Result<PersistStatus, Error> {
        let p = format!("{:020}.routes", rt.registry_version);
        let p = self.routes_dir.join(p);

        let w = File::create(p).context("failed to create routes file")?;
        let w = BufWriter::new(w);
        serde_json::to_writer(w, &rt).context("failed to write json routes file")?;

        Ok(PersistStatus::Completed)
    }
}

#[async_trait]
trait Run: Send + Sync {
    async fn run(&mut self) -> Result<(), Error>;
}

struct SnapshotRunner<S: Snapshot> {
    snapshotter: S,
    routing_table: Arc<Mutex<Option<RoutingTable>>>,
}

impl<S: Snapshot> SnapshotRunner<S> {
    fn new(snapshotter: S, routing_table: Arc<Mutex<Option<RoutingTable>>>) -> Self {
        Self {
            snapshotter,
            routing_table,
        }
    }
}

#[async_trait]
impl<S: Snapshot> Run for SnapshotRunner<S> {
    async fn run(&mut self) -> Result<(), Error> {
        let routing_table = self
            .snapshotter
            .snapshot()
            .await
            .context("failed to obtain registry snapshot")?;

        let mut _routing_table = self.routing_table.lock().unwrap();
        *_routing_table = Some(routing_table);

        Ok(())
    }
}

struct CheckPersistRunner<C: Check, P: Persist> {
    routing_table: Arc<Mutex<Option<RoutingTable>>>,
    checker: Arc<C>,
    persister: P,
}

impl<C: Check, P: Persist> CheckPersistRunner<C, P> {
    fn new(routing_table: Arc<Mutex<Option<RoutingTable>>>, checker: C, persister: P) -> Self {
        Self {
            routing_table,
            checker: Arc::new(checker),
            persister,
        }
    }
}

#[async_trait]
impl<C: Check, P: Persist> Run for CheckPersistRunner<C, P> {
    async fn run(&mut self) -> Result<(), Error> {
        let routing_table = {
            let rt = self.routing_table.lock().unwrap();
            rt.clone()
                .ok_or_else(|| anyhow!("routing_table not available"))?
        };

        let check_results: Arc<DashSet<(String, String)>> = Arc::new(DashSet::new());

        // Perform Health Checks
        let futs = FuturesUnordered::new();

        for subnet in routing_table.clone().subnets {
            for node in subnet.nodes {
                let checker = Arc::clone(&self.checker);
                let check_results = Arc::clone(&check_results);

                let (subnet_id, node_id, socket_addr) = (
                    subnet.subnet_id.clone(),
                    node.node_id.clone(),
                    node.socket_addr.clone(),
                );

                futs.push(task::spawn(async move {
                    let _ctx = opentelemetry::Context::current_with_baggage(vec![
                        KeyValue::new("subnet_id", subnet_id.to_string()),
                        KeyValue::new("node_id", node_id.to_string()),
                        KeyValue::new("socket_addr", socket_addr.to_string()),
                    ]);

                    let out = checker
                        .check(&socket_addr)
                        .with_context(_ctx.clone())
                        .await
                        .context("failed to check node");

                    if out.is_ok() {
                        check_results.insert((subnet_id, node_id));
                    }

                    out
                }));
            }
        }

        for fut in futs {
            let _ = fut.await?;
        }

        // Construct Effective Routing Table
        let effective_routing_table = RoutingTable {
            subnets: routing_table
                .subnets
                .into_iter()
                .map(|subnet| Subnet {
                    nodes: subnet
                        .nodes
                        .into_iter()
                        .filter(|node| {
                            check_results
                                .contains(&(subnet.subnet_id.clone(), node.node_id.clone()))
                        })
                        .collect(),
                    ..subnet
                })
                .collect(),
            ..routing_table
        };

        // Persist Effective Routing Table
        self.persister
            .persist(effective_routing_table)
            .await
            .context("failed to persist routing table")?;

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
impl<T: Run + Send + Sync> Run for WithThrottle<T> {
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

struct WithSemaphore<T>(T, Semaphore);

impl<T> WithSemaphore<T> {
    fn wrap(t: T, permits: usize) -> Self {
        Self(t, Semaphore::new(permits))
    }
}

#[async_trait]
impl<T: Check> Check for WithSemaphore<T> {
    async fn check(&self, addr: &str) -> Result<(), Error> {
        let _permit = self.1.acquire().await?;
        self.0.check(addr).await
    }
}

struct WithDedup<T, U>(T, Option<U>);

#[async_trait]
impl<T: Persist> Persist for WithDedup<T, RoutingTable> {
    async fn persist(&mut self, rt: RoutingTable) -> Result<PersistStatus, Error> {
        if self.1.as_ref() == Some(&rt) {
            return Ok(PersistStatus::Skipped);
        } else {
            self.1 = Some(rt.clone());
        }

        self.0.persist(rt).await
    }
}
