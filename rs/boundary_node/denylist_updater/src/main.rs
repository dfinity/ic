use std::{
    io::ErrorKind,
    net::SocketAddr,
    path::PathBuf,
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
use clap::Parser;
use futures::future::TryFutureExt;
use mockall::automock;
use nix::{
    sys::signal::{kill as send_signal, Signal},
    unistd::Pid,
};
use opentelemetry::{global, sdk::Resource, KeyValue};
use opentelemetry_prometheus::PrometheusExporter;
use prometheus::{Encoder, TextEncoder};
use serde::Deserialize;
use tokio::{
    fs::{self, File},
    io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader},
    task,
};
use tracing::info;

mod metrics;
use metrics::{MetricParams, WithMetrics};

const SERVICE_NAME: &str = "denylist-updater";

const MINUTE: Duration = Duration::from_secs(60);

#[derive(Parser)]
#[clap(name = SERVICE_NAME)]
#[clap(author = "Boundary Node Team <boundary-nodes@dfinity.org>")]
struct Cli {
    #[clap(long, default_value = "http://localhost:8000/denylist.json")]
    remote_url: String,

    #[clap(long, default_value = "/tmp/denylist.map")]
    local_path: PathBuf,

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

    let exporter = opentelemetry_prometheus::exporter()
        .with_resource(Resource::new(vec![KeyValue::new("service", SERVICE_NAME)]))
        .init();

    let meter = global::meter(SERVICE_NAME);

    let metrics_handler = metrics_handler.layer(Extension(MetricsHandlerArgs { exporter }));
    let metrics_router = Router::new().route("/metrics", get(metrics_handler));

    let http_client = reqwest::Client::builder().build()?;

    let remote_lister = RemoteLister::new(http_client, cli.remote_url.clone());
    let remote_lister = WithNormalize(remote_lister);
    let remote_lister = WithMetrics(
        remote_lister,
        MetricParams::new(&meter, SERVICE_NAME, "list_local"),
    );

    let local_lister = LocalLister::new(cli.local_path.clone());
    let local_lister = WithRecover(local_lister);
    let local_lister = WithNormalize(local_lister);
    let local_lister = WithMetrics(
        local_lister,
        MetricParams::new(&meter, SERVICE_NAME, "list_remote"),
    );

    let reloader = Reloader::new(cli.pid_path, Signal::SIGHUP);
    let reloader = WithMetrics(reloader, MetricParams::new(&meter, SERVICE_NAME, "reload"));

    let updater = Updater::new(cli.local_path.clone());
    let updater = WithReload(updater, reloader);
    let updater = WithMetrics(updater, MetricParams::new(&meter, SERVICE_NAME, "update"));

    let runner = Runner::new(remote_lister, local_lister, updater);
    let runner = WithMetrics(runner, MetricParams::new(&meter, SERVICE_NAME, "run"));
    let runner = WithThrottle(runner, ThrottleParams::new(1 * MINUTE));
    let mut runner = runner;

    info!(
        msg = format!("starting {SERVICE_NAME}").as_str(),
        metrics_addr = cli.metrics_addr.to_string().as_str(),
    );

    let _ = tokio::try_join!(
        task::spawn(async move {
            loop {
                let _ = runner.run().await;
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

#[derive(Debug, PartialEq, Deserialize)]
struct Entry {
    id: String,
    #[allow(dead_code)]
    code: String,
    #[allow(dead_code)]
    reason: String,
}

#[automock]
#[async_trait]
trait List: Send + Sync {
    async fn list(&self) -> Result<Vec<Entry>, Error>;
}

struct LocalLister {
    local_path: PathBuf,
}

impl LocalLister {
    fn new(local_path: PathBuf) -> Self {
        Self { local_path }
    }
}

#[async_trait]
impl List for LocalLister {
    async fn list(&self) -> Result<Vec<Entry>, Error> {
        let f = File::open(self.local_path.clone())
            .await
            .context("failed to open file")?;

        let f = BufReader::new(f);

        let mut lines = f.lines();
        let mut entries = vec![];

        while let Some(line) = lines.next_line().await? {
            if let Some(id) = line.split_whitespace().next() {
                entries.push(Entry {
                    id: id.to_string(),
                    code: "N/A".to_string(),
                    reason: "N/A".to_string(),
                });
            }
        }

        Ok(entries)
    }
}

struct RemoteLister {
    http_client: reqwest::Client,
    remote_url: String,
}

impl RemoteLister {
    fn new(http_client: reqwest::Client, remote_url: String) -> Self {
        Self {
            http_client,
            remote_url,
        }
    }
}

#[async_trait]
impl List for RemoteLister {
    async fn list(&self) -> Result<Vec<Entry>, Error> {
        let request = self
            .http_client
            .request(reqwest::Method::GET, self.remote_url.clone())
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

        let entries = response
            .json::<Vec<Entry>>()
            .await
            .context("failed to deserialize response")?;

        Ok(entries)
    }
}

#[automock]
#[async_trait]
trait Update: Send + Sync {
    async fn update(&self, entries: Vec<Entry>) -> Result<(), Error>;
}

struct Updater {
    local_path: PathBuf,
}

impl Updater {
    fn new(local_path: PathBuf) -> Self {
        Self { local_path }
    }
}

#[async_trait]
impl Update for Updater {
    async fn update(&self, entries: Vec<Entry>) -> Result<(), Error> {
        let mut f = File::create(self.local_path.clone())
            .await
            .context("failed to create file")?;

        for entry in entries {
            let line = format!("{} 1;\n", entry.id);

            f.write(line.as_bytes())
                .await
                .context("failed to write entry")?;
        }

        Ok(())
    }
}

#[async_trait]
trait Reload: Sync + Send {
    async fn reload(&self) -> Result<(), Error>;
}

struct Reloader {
    pid_path: PathBuf,
    signal: Signal,
}

impl Reloader {
    fn new(pid_path: PathBuf, signal: Signal) -> Self {
        Self { pid_path, signal }
    }
}

#[async_trait]
impl Reload for Reloader {
    async fn reload(&self) -> Result<(), Error> {
        let pid = fs::read_to_string(self.pid_path.clone())
            .await
            .context("failed to read pid file")?;
        let pid = pid.parse::<i32>().context("failed to parse pid")?;
        let pid = Pid::from_raw(pid);

        send_signal(pid, self.signal)?;

        Ok(())
    }
}

struct WithReload<T, R: Reload>(T, R);

#[async_trait]
impl<T: Update, R: Reload> Update for WithReload<T, R> {
    async fn update(&self, entries: Vec<Entry>) -> Result<(), Error> {
        let out = self.0.update(entries).await?;
        self.1.reload().await?;
        Ok(out)
    }
}

#[async_trait]
trait Run: Send + Sync {
    async fn run(&mut self) -> Result<(), Error>;
}

struct Runner<RL, LL, U> {
    remote_lister: RL,
    local_lister: LL,
    updater: U,
}

impl<RL: List, LL: List, U: Update> Runner<RL, LL, U> {
    fn new(remote_lister: RL, local_lister: LL, updater: U) -> Self {
        Self {
            remote_lister,
            local_lister,
            updater,
        }
    }
}

#[async_trait]
impl<RL: List, LL: List, U: Update> Run for Runner<RL, LL, U> {
    async fn run(&mut self) -> Result<(), Error> {
        let remote_entries = self
            .remote_lister
            .list()
            .await
            .context("failed to list remote entries")?;

        let local_entries = self
            .local_lister
            .list()
            .await
            .context("failed to list local entrie")?;

        if !eq(&remote_entries, &local_entries) {
            self.updater
                .update(remote_entries)
                .await
                .context("failed to update entries")?;
        }

        Ok(())
    }
}

fn eq(a: &[Entry], b: &[Entry]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let (mut a, mut b) = (a.iter(), b.iter());
    while let (Some(a), Some(b)) = (a.next(), b.next()) {
        if a.id != b.id {
            return false;
        }
    }

    true
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

struct WithNormalize<T: List>(T);

#[async_trait]
impl<T: List> List for WithNormalize<T> {
    async fn list(&self) -> Result<Vec<Entry>, Error> {
        self.0
            .list()
            .await
            .map(|mut entries| {
                entries.sort_by(|a, b| a.id.cmp(&b.id));
                entries
            })
            .map(|mut entries| {
                entries.dedup_by(|a, b| a.id == b.id);
                entries
            })
    }
}

struct WithRecover<T: List>(T);

#[async_trait]
impl<T: List> List for WithRecover<T> {
    async fn list(&self) -> Result<Vec<Entry>, Error> {
        match self.0.list().await {
            Err(err) => match io_error_kind(&err) {
                Some(ErrorKind::NotFound) => Ok(vec![]),
                _ => Err(err),
            },
            Ok(entries) => Ok(entries),
        }
    }
}

fn io_error_kind(err: &Error) -> Option<ErrorKind> {
    for cause in err.chain() {
        if let Some(err) = cause.downcast_ref::<io::Error>() {
            return Some(err.kind());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use mockall::predicate;

    #[tokio::test]
    async fn it_lists_locally() -> Result<(), Error> {
        use std::fs::File;
        use std::io::Write;
        use tempfile::tempdir;

        // Create route files
        let local_dir = tempdir()?;

        let (name, content) = &("denylist.map", "ID_1 1;\nID_2 1;");

        let file_path = local_dir.path().join(name);
        let mut file = File::create(file_path.clone())?;
        writeln!(file, "{}", content)?;

        // Create local lister
        let lister = LocalLister::new(file_path.clone());

        let out = lister.list().await?;
        assert_eq!(
            out,
            vec![
                Entry {
                    id: "ID_1".to_string(),
                    code: "N/A".to_string(),
                    reason: "N/A".to_string(),
                },
                Entry {
                    id: "ID_2".to_string(),
                    code: "N/A".to_string(),
                    reason: "N/A".to_string(),
                }
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn it_runs_eq_empty() -> Result<(), Error> {
        let mut remote_lister = MockList::new();
        remote_lister
            .expect_list()
            .times(1)
            .returning(|| Ok(vec![]));

        let mut local_lister = MockList::new();
        local_lister.expect_list().times(1).returning(|| Ok(vec![]));

        let mut updater = MockUpdate::new();
        updater.expect_update().times(0);

        let mut runner = Runner::new(remote_lister, local_lister, updater);
        runner.run().await?;

        Ok(())
    }

    #[tokio::test]
    async fn it_runs_eq_non_empty() -> Result<(), Error> {
        let mut remote_lister = MockList::new();
        remote_lister.expect_list().times(1).returning(|| {
            Ok(vec![Entry {
                id: "ID_1".to_string(),
                code: "CODE_1".to_string(),
                reason: "REASON_1".to_string(),
            }])
        });

        let mut local_lister = MockList::new();
        local_lister.expect_list().times(1).returning(|| {
            Ok(vec![Entry {
                id: "ID_1".to_string(),
                code: "CODE_1".to_string(),
                reason: "REASON_1".to_string(),
            }])
        });

        let mut updater = MockUpdate::new();
        updater.expect_update().times(0);

        let mut runner = Runner::new(remote_lister, local_lister, updater);
        runner.run().await?;

        Ok(())
    }

    #[tokio::test]
    async fn it_runs_neq() -> Result<(), Error> {
        let mut remote_lister = MockList::new();
        remote_lister.expect_list().times(1).returning(|| {
            Ok(vec![Entry {
                id: "ID_1".to_string(),
                code: "CODE_1".to_string(),
                reason: "REASON_1".to_string(),
            }])
        });

        let mut local_lister = MockList::new();
        local_lister.expect_list().times(1).returning(|| Ok(vec![]));

        let mut updater = MockUpdate::new();
        updater
            .expect_update()
            .times(1)
            .with(predicate::function(|entries: &Vec<Entry>| {
                eq(
                    entries,
                    &[Entry {
                        id: "ID_1".to_string(),
                        code: "CODE_1".to_string(),
                        reason: "REASON_1".to_string(),
                    }],
                )
            }))
            .returning(|_| Ok(()));

        let mut runner = Runner::new(remote_lister, local_lister, updater);
        runner.run().await?;

        Ok(())
    }
}
