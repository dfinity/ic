use std::{
    io::BufRead,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::State,
    http::{Request, Response, StatusCode},
    routing::get,
    Router,
};
use clap::Parser;
use futures::future::TryFutureExt;
use lazy_static::lazy_static;
use nix::sys::signal::Signal;
use opentelemetry::{
    global,
    sdk::{
        export::metrics::aggregation,
        metrics::{controllers, processors, selectors},
        Resource,
    },
    KeyValue,
};
use opentelemetry_prometheus::{ExporterBuilder, PrometheusExporter};
use prometheus::proto::MetricFamily;
use prometheus::{Encoder as PrometheusEncoder, TextEncoder};

use regex::Regex;
use tokio::{sync::Semaphore, task};
use tracing::info;

mod check;
mod encode;
mod metrics;
mod persist;
mod registry;
mod reload;
mod retry;
mod routes;

use crate::{
    check::{ActiveChecker, Check, CheckPersistRunner, CheckResult, Checker},
    encode::{RoutesEncoder, SystemReplicasEncoder, TrustedCertsEncoder, UpstreamEncoder},
    metrics::{CheckMetricParams, CheckWithMetrics, MetricParams, WithMetrics},
    persist::{
        LegacyPersister, Persist, PersistStatus, Persister, WithDedup, WithEmpty, WithMultiple,
    },
    registry::{
        CreateRegistryClient, CreateRegistryClientImpl, RoutingTable, Snapshot, Snapshotter,
        WithMinimumVersion,
    },
    reload::{PidReloader, SystemdReloader, WithReload},
    retry::WithRetry,
};

const SERVICE_NAME: &str = "control-plane";
const CHECKER_METRIC_PREFIX: &str = "control_plane_check_";

const SECOND: Duration = Duration::from_secs(1);
const MINUTE: Duration = Duration::from_secs(60);

lazy_static! {
    static ref RE_NODE_ID: Regex = Regex::new(r#"\{.*node_id="([a-zA-Z0-9\\-]*)".*}"#).unwrap();
    static ref RE_SUBNET_ID: Regex = Regex::new(r#"\{.*subnet_id="([a-zA-Z0-9\\-]*)".*}"#).unwrap();
}

#[derive(Parser)]
#[clap(name = SERVICE_NAME)]
#[clap(author = "Boundary Node Team <boundary-nodes@dfinity.org>")]
struct Cli {
    #[clap(long, default_value = "/tmp/store")]
    local_store: PathBuf,

    #[clap(long, default_value = "0")]
    min_registry_version: u64,

    /// Minimum required OK health checks
    /// for a replica to be included in the routing table
    #[clap(long, default_value = "1")]
    min_ok_count: u8,

    // Timeout for the whole HTTP request in seconds
    #[clap(long, default_value = "2")]
    http_timeout: u64,

    // Timeout for the HTTP connect phase in seconds
    #[clap(long, default_value = "1")]
    http_timeout_connect: u64,

    // How frequently to run node checks in seconds
    #[clap(long, default_value = "10")]
    check_interval: u64,

    // How many attempts to do when checking a node
    #[clap(long, default_value = "3")]
    check_retries: u32,

    // How long to wait between retries in seconds
    #[clap(long, default_value = "1")]
    check_retry_interval: u64,

    // How many nodes to check concurrently
    #[clap(long, default_value = "64")]
    concurrency: usize,

    /// Maximum block height lag for a replica to be included in the routing table
    #[clap(long, default_value = "1000")]
    max_height_lag: u64,

    #[clap(long, default_value = "/tmp/legacy_routes")]
    legacy_routes_dir: PathBuf,

    #[clap(long, default_value = "/tmp/routes.js")]
    routes_path: PathBuf,

    #[clap(long, default_value = "/tmp/upstreams.conf")]
    upstreams_path: PathBuf,

    #[clap(long, default_value = "/tmp/trusted_certs.pem")]
    trusted_certs_path: PathBuf,

    #[clap(long, default_value = "/tmp/system_replicas.ruleset")]
    nftables_system_replicas_path: PathBuf,

    #[clap(long, default_value = "system_replica_ips")]
    nftables_system_replicas_var: String,

    #[clap(long, default_value = "/usr/bin/systemctl")]
    systemctl_path: PathBuf,

    #[clap(long, default_value = "/var/run/nginx.pid")]
    pid_path: PathBuf,

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

    let exporter = Arc::new(
        ExporterBuilder::new(
            controllers::basic(
                processors::factory(
                    selectors::simple::histogram([]),
                    aggregation::cumulative_temporality_selector(),
                )
                .with_memory(true),
            )
            .with_resource(Resource::new(vec![KeyValue::new("service", SERVICE_NAME)]))
            .build(),
        )
        .init(),
    );

    // Metrics
    let meter = global::meter(SERVICE_NAME);

    // Control-Plane
    let routing_table: Arc<Mutex<Option<RoutingTable>>> = Arc::new(Mutex::new(None));

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cli.http_timeout))
        .connect_timeout(Duration::from_secs(cli.http_timeout_connect))
        .build()?;

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

    let checker_metrics: Vec<MetricFamily> = Vec::new();
    let checker_metrics = Arc::new(ArcSwap::from_pointee(checker_metrics));

    let checker = Checker::new(http_client);
    let checker = CheckWithMetrics(
        checker,
        CheckMetricParams::new(&meter, SERVICE_NAME, "check"),
    );
    let checker = WithRetry(
        checker,
        cli.check_retries,                             // max_attempts
        Duration::from_secs(cli.check_retry_interval), // attempt_interval
    );
    let checker = WithSemaphore::wrap(checker, cli.concurrency);

    // Service Reloads
    let ngx_reloader = PidReloader::new(cli.pid_path, Signal::SIGHUP);
    let ngx_reloader = WithMetrics(
        ngx_reloader,
        MetricParams::new(&meter, SERVICE_NAME, "ngx_reload"),
    );

    let nft_reloader = SystemdReloader::new(
        cli.systemctl_path, // bin_path
        "nftables",         // service
        "restart",          // command
    );
    let nft_reloader = WithMetrics(
        nft_reloader,
        MetricParams::new(&meter, SERVICE_NAME, "nftables_reload"),
    );

    // Persistence
    let persister = WithMultiple(vec![
        Arc::new(WithReload(
            WithMultiple(vec![
                Arc::new(LegacyPersister::new(cli.legacy_routes_dir.clone())),
                Arc::new(Persister::new(
                    cli.routes_path.clone(),
                    Arc::new(RoutesEncoder),
                )),
                Arc::new(Persister::new(
                    cli.upstreams_path.clone(),
                    Arc::new(UpstreamEncoder),
                )),
                Arc::new(Persister::new(
                    cli.trusted_certs_path.clone(),
                    Arc::new(TrustedCertsEncoder),
                )),
            ]),
            ngx_reloader,
        )),
        Arc::new(WithReload(
            WithMultiple(vec![Arc::new(Persister::new(
                cli.nftables_system_replicas_path.clone(),
                Arc::new(SystemReplicasEncoder(cli.nftables_system_replicas_var)),
            ))]),
            nft_reloader,
        )),
    ]);

    let persister = WithDedup(persister, Arc::new(RwLock::new(None)));
    let persister = WithEmpty(persister);
    let persister = WithMetrics(
        persister,
        MetricParams::new(&meter, SERVICE_NAME, "persist"),
    );

    // Runner
    let check_persist_runner = CheckPersistRunner::new(
        Arc::clone(&routing_table),
        checker,
        persister,
        cli.min_ok_count,
        cli.max_height_lag,
    );
    let active_replicas = check_persist_runner.get_active_checker();
    let check_persist_runner = WithMetrics(
        check_persist_runner,
        MetricParams::new(&meter, SERVICE_NAME, "run"),
    );
    let check_persist_runner = WithThrottle(
        check_persist_runner,
        ThrottleParams::new(Duration::from_secs(cli.check_interval)),
    );
    let mut check_persist_runner = check_persist_runner;

    // Metrics
    let metrics_router = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(MetricsHandlerArgs {
            exporter: Arc::clone(&exporter),
            active_replicas,
            checker_metrics: Arc::clone(&checker_metrics),
        });

    info!(
        msg = format!("starting {SERVICE_NAME}"),
        legacy_routes_dir = %cli.legacy_routes_dir.display(),
        routes_path = %cli.routes_path.display(),
        upstreams_path = %cli.upstreams_path.display(),
        trusted_certs_path = %cli.trusted_certs_path.display(),
        metrics_addr = %cli.metrics_addr,
    );

    let _ = tokio::try_join!(
        task::spawn(async move {
            loop {
                let _ = snapshot_runner.run().await;
            }
        }),
        task::spawn(async move {
            let exporter = Arc::clone(&exporter);
            let checker_metrics = Arc::clone(&checker_metrics);

            loop {
                let _ = check_persist_runner.run().await;
                update_checker_metrics(&exporter, &checker_metrics);
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
struct MetricsHandlerArgs<A> {
    exporter: Arc<PrometheusExporter>,
    active_replicas: A,
    checker_metrics: Arc<ArcSwap<Vec<MetricFamily>>>,
}

// Gathers metrics relevant to node checking and stores them in the ArcSwap
fn update_checker_metrics(
    exporter: &Arc<PrometheusExporter>,
    checker_metrics: &Arc<ArcSwap<Vec<MetricFamily>>>,
) {
    // Gather node checker metrics
    let metric_families = Arc::new(
        exporter
            .registry()
            .gather()
            .into_iter()
            .filter(|x| x.get_name().starts_with(CHECKER_METRIC_PREFIX))
            .collect::<Vec<_>>(),
    );

    checker_metrics.store(metric_families);
}

async fn metrics_handler<A: ActiveChecker>(
    State(MetricsHandlerArgs {
        exporter,
        active_replicas,
        checker_metrics,
    }): State<MetricsHandlerArgs<A>>,
    _: Request<Body>,
) -> Response<Body> {
    // Read out all metrics that are not related to node checking
    let mut metric_families = exporter
        .registry()
        .gather()
        .into_iter()
        .filter(|x| !x.get_name().starts_with(CHECKER_METRIC_PREFIX))
        .collect::<Vec<_>>();

    // Concatenate node checking metrics with all others & sort the result to be consistent with gather() output
    let mut _checker_metrics = { Vec::clone(&checker_metrics.load()) };
    metric_families.append(&mut _checker_metrics);
    metric_families.sort_by(|a, b| a.get_name().cmp(b.get_name()));

    let encoder = TextEncoder::new();

    let mut metrics_text = Vec::new();
    if encoder.encode(&metric_families, &mut metrics_text).is_err() {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("Internal Server Error".into())
            .unwrap();
    };

    // Remove lines with status of stale replicas
    //
    // When replicas are removed from the registry we no longer run health checks for them.
    // When that happens, the last gauge value for those replicas never changes.
    // This pollutes our metrics with stale data. Therefore we remove metric lines corresponding
    // to replicas that are no longer being actively health-checked.
    let metrics_text = remove_stale(active_replicas, &metrics_text);

    Response::builder()
        .status(200)
        .body(metrics_text.into())
        .unwrap()
}

fn remove_stale<A: ActiveChecker>(active_replicas: A, metrics_text: &[u8]) -> Vec<u8> {
    metrics_text
        .lines()
        .flat_map(|ln| match ln {
            Ok(ln) => {
                // Skip lines that arent gauges
                if !ln.starts_with("control_plane_check_status{")
                    && !ln.starts_with("control_plane_check_block_height{")
                {
                    return Vec::from(format!("{ln}\n"));
                }

                // The gauge line should have both subnet and node ID labels
                let subnet_node_id = match extract_ids(&ln) {
                    Some(v) => v,
                    None => return Vec::from(format!("{ln}\n")),
                };

                // Checks should only contain active replicas
                match active_replicas.is_active(&subnet_node_id) {
                    true => Vec::from(format!("{ln}\n")),

                    // Stale
                    false => vec![],
                }
            }
            _ => vec![],
        })
        .collect()
}

fn extract_ids(s: &str) -> Option<(String, String)> {
    // Capture node ID
    if let Some(cptr) = RE_NODE_ID.captures(s) {
        if let Some(node_id) = cptr.get(1) {
            // Capture subnet ID
            if let Some(cptr) = RE_SUBNET_ID.captures(s) {
                if let Some(subnet_id) = cptr.get(1) {
                    return Some((
                        subnet_id.as_str().into(), // subnet_id
                        node_id.as_str().into(),   // node_id
                    ));
                }
            }
        }
    };

    None
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
    async fn check(&self, addr: &str) -> Result<CheckResult, Error> {
        let _permit = self.1.acquire().await?;
        self.0.check(addr).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_stale() {
        fn is_active(subnet_node_id: &(String, String)) -> bool {
            [
                (
                    "5kdm2-62fc6-fwnja-hutkz-ycsnm-4z33i-woh43-4cenu-ev7mi-gii6t-4ae".into(),
                    "kywkz-eopg4-nn6md-cjb24-5ri6y-aq6au-vt57i-kg7gk-ch5pw-7er3w-7qe".into(),
                ),
                (
                    "w4asl-4nmyj-qnr7c-6cqq4-tkwmt-o26di-iupkq-vx4kt-asbrx-jzuxh-4ae".into(),
                    "ze4ou-bfvbt-c5onv-3sxls-vqa4d-gwmt2-fr3zy-svzdq-ge2yd-oehb3-wqe".into(),
                ),
            ]
            .contains(subnet_node_id)
        }

        // middle line is stale
        let txt = [
            r#"control_plane_check_status{addr="[::1]:8080",node_id="kywkz-eopg4-nn6md-cjb24-5ri6y-aq6au-vt57i-kg7gk-ch5pw-7er3w-7qe",service="control-plane",subnet_id="5kdm2-62fc6-fwnja-hutkz-ycsnm-4z33i-woh43-4cenu-ev7mi-gii6t-4ae"} 1"#,
            r#"control_plane_check_status{addr="[::1]:8080",node_id="q6bis-oxwxg-eh76l-5i47b-nmcm7-wibd3-q5alp-j6hxy-puzh2-qgequ-bae",service="control-plane",subnet_id="x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae"} 1"#,
            r#"control_plane_check_status{addr="[::1]:8080",node_id="ze4ou-bfvbt-c5onv-3sxls-vqa4d-gwmt2-fr3zy-svzdq-ge2yd-oehb3-wqe",service="control-plane",subnet_id="w4asl-4nmyj-qnr7c-6cqq4-tkwmt-o26di-iupkq-vx4kt-asbrx-jzuxh-4ae"} 1"#,
        ].join("\n");

        let out = remove_stale(
            is_active,      // checks
            txt.as_bytes(), // metrics_text
        );

        let out = String::from_utf8(out).expect("failed to convert output to string");

        let txt = [
            r#"control_plane_check_status{addr="[::1]:8080",node_id="kywkz-eopg4-nn6md-cjb24-5ri6y-aq6au-vt57i-kg7gk-ch5pw-7er3w-7qe",service="control-plane",subnet_id="5kdm2-62fc6-fwnja-hutkz-ycsnm-4z33i-woh43-4cenu-ev7mi-gii6t-4ae"} 1"#,
            r#"control_plane_check_status{addr="[::1]:8080",node_id="ze4ou-bfvbt-c5onv-3sxls-vqa4d-gwmt2-fr3zy-svzdq-ge2yd-oehb3-wqe",service="control-plane",subnet_id="w4asl-4nmyj-qnr7c-6cqq4-tkwmt-o26di-iupkq-vx4kt-asbrx-jzuxh-4ae"} 1"#,
        ].join("\n");

        assert_eq!(out, txt + "\n");
    }

    #[test]
    fn extracts_ids_empty() {
        assert_eq!(extract_ids(""), None);
    }

    #[test]
    fn extracts_ids_ok() {
        assert_eq!(
            extract_ids(r#"{subnet_id="subnet-1",node_id="node-1"}"#),
            Some((String::from("subnet-1"), String::from("node-1"))),
        );
    }

    #[test]
    fn extracts_ids_invalid() {
        assert_eq!(extract_ids(r#"{subnet_id="subnet-1"}"#), None);
    }
}
