use std::{
    collections::hash_map::DefaultHasher,
    collections::HashMap,
    fs::{self, File},
    hash::{Hash, Hasher},
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
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
use clap::{ArgEnum, Parser};
use mockall::automock;
use nix::{
    sys::signal::{kill as send_signal, Signal},
    unistd::Pid,
};
use opentelemetry::metrics::MeterProvider;
use opentelemetry_prometheus::exporter;
use opentelemetry_sdk::metrics::MeterProviderBuilder;
use prometheus::{labels, Encoder, Registry, TextEncoder};
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use serde::Deserialize;
use serde_json as json;
use tokio::{net::TcpListener, task};
use tracing::info;

mod metrics;
use metrics::{MetricParams, WithMetrics};

mod decode;
use decode::{Decode, Decoder, NopDecoder};

const SERVICE_NAME: &str = "denylist-updater";

const MINUTE: Duration = Duration::from_secs(60);

#[derive(Clone, ArgEnum)]
enum DecodeMode {
    Nop,
    Decrypt,
}

#[derive(Parser)]
#[clap(name = SERVICE_NAME)]
#[clap(author = "Boundary Node Team <boundary-nodes@dfinity.org>")]
struct Cli {
    #[clap(long, default_value = "http://localhost:8000/denylist.json")]
    remote_url: String,

    #[clap(long, arg_enum, default_value = "nop")]
    decode_mode: DecodeMode,

    #[clap(long, default_value = "key.pem")]
    private_key_path: PathBuf,

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

    // Metrics
    let registry: Registry = Registry::new_custom(
        None,
        Some(labels! {"service".into() => SERVICE_NAME.into()}),
    )
    .unwrap();
    let exporter = exporter().with_registry(registry.clone()).build()?;
    let provider = MeterProviderBuilder::default()
        .with_reader(exporter)
        .build();
    let meter = provider.meter(SERVICE_NAME);
    let metrics_handler = metrics_handler.layer(Extension(MetricsHandlerArgs { registry }));
    let metrics_router = Router::new().route("/metrics", get(metrics_handler));

    let http_client = reqwest::Client::builder().build()?;

    let decoder: Arc<dyn Decode> = match cli.decode_mode {
        DecodeMode::Nop => Arc::new(NopDecoder),
        DecodeMode::Decrypt => {
            let private_key_pem = std::fs::read_to_string(cli.private_key_path)?;
            let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_pem)?;
            Arc::new(Decoder::new(private_key))
        }
    };

    let remote_lister = RemoteLister::new(http_client, decoder, cli.remote_url.clone());
    let remote_lister = WithNormalize(remote_lister);
    let remote_lister = WithMetrics(
        remote_lister,
        MetricParams::new(&meter, SERVICE_NAME, "list_remote"),
    );

    let reloader = Reloader::new(cli.pid_path, Signal::SIGHUP);
    let reloader = WithMetrics(reloader, MetricParams::new(&meter, SERVICE_NAME, "reload"));

    let updater = Updater::new(cli.local_path.clone());
    let updater = WithReload(updater, reloader);
    let updater = WithMetrics(updater, MetricParams::new(&meter, SERVICE_NAME, "update"));

    let runner = Runner::new(remote_lister, updater);
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
        task::spawn(async move {
            let listener = TcpListener::bind(&cli.metrics_addr).await.unwrap();
            axum::serve(listener, metrics_router.into_make_service())
                .await
                .map_err(|err| anyhow!("server failed: {:?}", err))
        })
    )
    .context(format!("{SERVICE_NAME} failed to run"))?;

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

#[derive(Clone, PartialEq, Hash, Debug, Deserialize)]
struct Entry {
    id: String,
    localities: Vec<String>,
}

#[derive(Clone, PartialEq, Hash, Debug, Deserialize)]
struct Entries(Vec<Entry>);

impl Entries {
    fn get_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.0.hash(&mut hasher);
        hasher.finish()
    }
}

#[automock]
#[async_trait]
trait List: Send + Sync {
    async fn list(&self) -> Result<Entries, Error>;
}

struct RemoteLister {
    http_client: reqwest::Client,
    decoder: Arc<dyn Decode>,
    remote_url: String,
}

impl RemoteLister {
    fn new(http_client: reqwest::Client, decoder: Arc<dyn Decode>, remote_url: String) -> Self {
        Self {
            http_client,
            decoder,
            remote_url,
        }
    }
}

#[async_trait]
impl List for RemoteLister {
    async fn list(&self) -> Result<Entries, Error> {
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

        let data = response
            .bytes()
            .await
            .context("failed to get response bytes")?
            .to_vec();

        let data = self
            .decoder
            .decode(data)
            .await
            .context("failed to decode response")?;

        #[derive(Deserialize)]
        struct Canister {
            localities: Option<Vec<String>>,
        }

        #[derive(Deserialize)]
        struct Response {
            canisters: HashMap<String, Canister>,
        }

        let entries =
            json::from_slice::<Response>(&data).context("failed to deserialize json response")?;

        // Convert response body to entries
        let mut entries: Vec<Entry> = entries
            .canisters
            .into_iter()
            .map(|(id, canister)| {
                let mut localities = canister.localities.unwrap_or_default();
                localities.sort();
                Entry { id, localities }
            })
            .collect();

        entries.sort_by(|a, b| a.id.cmp(&b.id));

        Ok(Entries(entries))
    }
}

#[automock]
trait Update: Send + Sync {
    fn update(&self, entries: Entries) -> Result<bool, Error>;
}

struct Updater {
    path: PathBuf,
    path_hash: PathBuf,
}

impl Updater {
    fn new(path: PathBuf) -> Self {
        let fname = path.file_name().unwrap().to_string_lossy();
        let dir = path.parent().unwrap();

        Self {
            path: path.clone(),
            path_hash: dir.join(format!("{fname}_hash")),
        }
    }

    fn get_hash(&self) -> Result<Option<u64>, Error> {
        if !Path::new(&self.path_hash).exists() {
            return Ok(None);
        }

        let x = fs::read_to_string(&self.path_hash).context("unable to read hash")?;
        x.parse::<u64>()
            .map(Some)
            .context("unable to parse hash as u64")
    }
}

impl Update for Updater {
    fn update(&self, entries: Entries) -> Result<bool, Error> {
        let new_hash = entries.get_hash();

        // If the hash exists and matches - do nothing
        if self.get_hash()? == Some(new_hash) {
            return Ok(false);
        }

        let mut f = File::create(&self.path).context("failed to create file")?;

        for entry in entries.0 {
            if entry.localities.is_empty() {
                writeln!(&f, "\"{}\" \"1\";", entry.id)?;
            } else {
                for loc in entry.localities {
                    writeln!(&f, "\"{}+{}\" \"1\";", entry.id, loc)?;
                }
            };
        }

        f.flush()?;

        // Write out the new hash
        fs::write(&self.path_hash, format!("{new_hash}")).context("unable to write hash file")?;

        Ok(true)
    }
}

trait Reload: Sync + Send {
    fn reload(&self) -> Result<(), Error>;
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

impl Reload for Reloader {
    fn reload(&self) -> Result<(), Error> {
        let pid = fs::read_to_string(self.pid_path.clone()).context("failed to read pid file")?;
        let pid = pid.trim().parse::<i32>().context("failed to parse pid")?;
        let pid = Pid::from_raw(pid);

        send_signal(pid, self.signal)?;

        Ok(())
    }
}

struct WithReload<T, R: Reload>(T, R);

impl<T: Update, R: Reload> Update for WithReload<T, R> {
    fn update(&self, entries: Entries) -> Result<bool, Error> {
        let r = self.0.update(entries)?;

        if r {
            self.1.reload()?;
        }

        Ok(r)
    }
}

#[async_trait]
trait Run: Send + Sync {
    async fn run(&mut self) -> Result<(), Error>;
}

struct Runner<RL, U> {
    remote_lister: RL,
    updater: U,
}

impl<RL: List, U: Update> Runner<RL, U> {
    fn new(remote_lister: RL, updater: U) -> Self {
        Self {
            remote_lister,
            updater,
        }
    }
}

#[async_trait]
impl<RL: List, U: Update> Run for Runner<RL, U> {
    async fn run(&mut self) -> Result<(), Error> {
        let remote_entries = self
            .remote_lister
            .list()
            .await
            .context("failed to list remote entries")?;

        self.updater
            .update(remote_entries)
            .context("failed to update entries")?;

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

struct WithNormalize<T: List>(T);

#[async_trait]
impl<T: List> List for WithNormalize<T> {
    async fn list(&self) -> Result<Entries, Error> {
        self.0
            .list()
            .await
            .map(|mut entries| {
                entries.0.sort_by(|a, b| a.id.cmp(&b.id));
                entries
            })
            .map(|mut entries| {
                entries.0.dedup_by(|a, b| a.id == b.id);
                entries
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_lists_remotely() -> Result<(), Error> {
        use httptest::{matchers::*, responders::*, Expectation, Server};
        use serde_json::json;

        struct TestCase {
            name: &'static str,
            denylist_json: json::Value,
            want: Entries,
        }

        let test_cases = vec![
            TestCase {
                name: "legacy",
                denylist_json: json!({
                  "$schema": "./schema.json",
                  "version": "1",
                  "canisters": {
                    "ID_1": {},
                    "ID_2": {}
                  }
                }),
                want: Entries(vec![
                    Entry {
                        id: "ID_1".to_string(),
                        localities: Vec::default(),
                    },
                    Entry {
                        id: "ID_2".to_string(),
                        localities: Vec::default(),
                    },
                ]),
            },
            TestCase {
                name: "geo_blocking",
                denylist_json: json!({
                  "$schema": "./schema.json",
                  "version": "1",
                  "canisters": {
                    "ID_1": {"localities": ["CH", "US"]},
                    "ID_2": {"localities": []},
                    "ID_3": {},
                  }
                }),
                want: Entries(vec![
                    Entry {
                        id: "ID_1".to_string(),
                        localities: vec!["CH".to_string(), "US".to_string()],
                    },
                    Entry {
                        id: "ID_2".to_string(),
                        localities: Vec::default(),
                    },
                    Entry {
                        id: "ID_3".to_string(),
                        localities: Vec::default(),
                    },
                ]),
            },
        ];

        for tc in test_cases {
            let server = Server::run();
            server.expect(
                Expectation::matching(request::method_path("GET", "/denylist.json"))
                    .respond_with(json_encoded(tc.denylist_json)),
            );

            // Create remote lister
            let lister = RemoteLister::new(
                reqwest::Client::builder().build()?, // http_client
                Arc::new(NopDecoder),                // decoder
                server.url_str("/denylist.json"),    // remote_url
            );

            let was = lister.list().await?;
            assert_eq!(was, tc.want, "Test case '{}' failed.\n", tc.name);
        }

        Ok(())
    }

    #[tokio::test]
    async fn it_updates() -> Result<(), Error> {
        use tempfile::tempdir;

        struct TestCase {
            name: &'static str,
            entries: Entries,
            want: &'static str,
        }

        let test_cases = vec![
            TestCase {
                name: "US",
                entries: Entries(vec![Entry {
                    id: "ID_1".to_string(),
                    localities: vec!["US".to_string()],
                }]),
                want: "\"ID_1+US\" \"1\";\n",
            },
            TestCase {
                name: "CH US",
                entries: Entries(vec![Entry {
                    id: "ID_1".to_string(),
                    localities: vec!["CH".to_string(), "US".to_string()],
                }]),
                want: "\"ID_1+CH\" \"1\";\n\"ID_1+US\" \"1\";\n",
            },
            TestCase {
                name: "global",
                entries: Entries(vec![
                    Entry {
                        id: "ID_1".to_string(),
                        localities: Vec::default(),
                    },
                    Entry {
                        id: "ID_2".to_string(),
                        localities: Vec::default(),
                    },
                ]),
                want: "\"ID_1\" \"1\";\n\"ID_2\" \"1\";\n",
            },
        ];

        for tc in test_cases {
            let local_dir = tempdir()?;
            let file_path = local_dir.path().join("denylist.map");

            // Create local lister
            let updater = Updater::new(file_path.clone());
            updater.update(tc.entries)?;

            let was = fs::read_to_string(file_path)?;
            assert_eq!(was, tc.want, "Test case '{}' failed.\n", tc.name);
        }

        Ok(())
    }
}
