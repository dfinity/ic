// TODO: remove
#![allow(unused)]

use std::{
    fs::File,
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
    extract::{DefaultBodyLimit, State},
    handler::Handler,
    middleware,
    routing::method_routing::{get, post},
    Extension, Router,
};
use axum_server::{accept::DefaultAcceptor, Server};
use clap::Parser;
use configuration::{Configure, ServiceConfiguration};
use futures::TryFutureExt;
use http::{header::HeaderName, Request, Response};
use hyper_rustls::ConfigBuilderExt;
use ic_registry_client::client::{RegistryClient, RegistryClientImpl};
use ic_registry_local_store::LocalStoreImpl;
use ic_registry_replicator::RegistryReplicator;
use instant_acme::{Account, AccountCredentials, LetsEncrypt, NewAccount};
use lazy_static::lazy_static;
use nns::Load;
use opentelemetry::{
    global,
    metrics::{Counter, Histogram},
    sdk::{
        export::metrics::aggregation,
        metrics::{controllers, processors, selectors},
        Resource,
    },
    KeyValue,
};
use opentelemetry_prometheus::{ExporterBuilder, PrometheusExporter};
use prometheus::{labels, Encoder as PrometheusEncoder, TextEncoder};
use tokio::sync::{Mutex, RwLock};
use tower::ServiceBuilder;
use tower_http::{
    request_id::{
        MakeRequestId, MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
    },
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
    ServiceBuilderExt,
};
use tracing::{error, info};
use url::Url;

use crate::{
    acme::Acme,
    check::{Checker, Runner as CheckRunner},
    configuration::{Configurator, FirewallConfigurator, TlsConfigurator, WithDeduplication},
    metrics::{MetricParams, WithMetrics},
    nns::Loader,
    routes::{MiddlewareState, ProxyRouter},
    snapshot::{DnsResolver, Runner as SnapshotRunner, TlsVerifier},
};

#[cfg(feature = "tls")]
use crate::tls::{CustomAcceptor, Provisioner, TokenSetter, WithLoad, WithStore};

mod acme;
mod check;
mod configuration;
mod firewall;
mod metrics;
mod nns;
mod persist;
mod routes;
mod snapshot;
#[cfg(feature = "tls")]
mod tls;

const SERVICE_NAME: &str = "ic-boundary";

const SECOND: Duration = Duration::from_secs(1);
const MINUTE: Duration = Duration::from_secs(60);
const DAY: Duration = Duration::from_secs(24 * 3600);

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

    // Port to listen for HTTP
    #[clap(long, default_value = "80")]
    http_port: u16,

    // Port to listen for HTTPS
    #[cfg(feature = "tls")]
    #[clap(long, default_value = "443")]
    https_port: u16,

    // Timeout for the whole HTTP request in seconds
    #[clap(long, default_value = "4")]
    http_timeout: u64,

    // Timeout for the HTTP connect phase in seconds
    #[clap(long, default_value = "2")]
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
    #[clap(long, default_value = "system_replicas.ruleset")]
    nftables_system_replicas_path: PathBuf,

    /// The name of the nftables variable to export
    #[clap(long, default_value = "system_replica_ips")]
    nftables_system_replicas_var: String,

    /// The path to the ACME credentials file
    #[cfg(feature = "tls")]
    #[clap(long, default_value = "acme.json")]
    acme_credentials_path: PathBuf,

    /// The path to the ingress TLS cert
    #[cfg(feature = "tls")]
    #[clap(long, default_value = "cert.pem")]
    tls_cert_path: PathBuf,

    /// The path to the ingress TLS private-key
    #[cfg(feature = "tls")]
    #[clap(long, default_value = "pkey.pem")]
    tls_pkey_path: PathBuf,

    /// The socket used to export metrics.
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
    let exporter = ExporterBuilder::new(
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
    .init();

    let meter = global::meter(SERVICE_NAME);

    let metrics_router = Router::new()
        .route("/metrics", get(metrics::metrics_handler))
        .with_state(metrics::MetricsHandlerArgs { exporter });

    info!(
        msg = format!("Starting {SERVICE_NAME}"),
        metrics_addr = cli.metrics_addr.to_string().as_str(),
    );

    let lookup_table = Arc::new(ArcSwapOption::empty());
    let routing_table = Arc::new(ArcSwapOption::empty());

    // HTTP Client
    let tls_verifier = TlsVerifier::new(Arc::clone(&routing_table));
    let dns_resolver = DnsResolver::new(Arc::clone(&routing_table));

    let rustls_config = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("unable to build Rustls config")?
        .with_custom_certificate_verifier(Arc::new(tls_verifier))
        .with_no_client_auth();

    let http_client = Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(cli.http_timeout))
            .connect_timeout(Duration::from_secs(cli.http_timeout_connect))
            .use_preconfigured_tls(rustls_config)
            .dns_resolver(Arc::new(dns_resolver))
            .build()
            .context("unable to build HTTP client")?,
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

    #[cfg(feature = "tls")]
    let (tls_configurator, tls_acceptor, token) =
        prepare_tls(&cli).await.context("unable to prepare TLS")?;

    // No-op configurator is used to make compiler/clippy happy
    // Otherwise the enums in Configurator become single-variant and it complains
    #[cfg(not(feature = "tls"))]
    let tls_configurator = TlsConfigurator {};

    // Firewall Configuration
    let fw_configurator = FirewallConfigurator {};
    let fw_configurator = WithDeduplication::wrap(fw_configurator);
    let fw_configurator = WithMetrics(
        fw_configurator,
        MetricParams::new(&meter, SERVICE_NAME, "configure_firewall"),
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
        MetricParams::new(&meter, SERVICE_NAME, "run_configuration"),
    );
    let configuration_runner = WithThrottle(configuration_runner, ThrottleParams::new(10 * SECOND));
    let mut configuration_runner = configuration_runner;

    // Server / API
    let proxy_router = Arc::new(ProxyRouter::new(
        Arc::clone(&http_client),
        Arc::clone(&lookup_table),
        nns_pub_key.into_bytes().into(),
    ));

    let state = MiddlewareState {
        proxier: proxy_router,
        metric_params: metrics::HttpMetricParams::new(&meter, SERVICE_NAME, "http_request"),
    };
    let routers_https: Router<_> = Router::new()
        .route("/api/v2/status", get(routes::status))
        .route("/api/v2/canister/:canister_id/query", post(routes::query))
        .route("/api/v2/canister/:canister_id/call", post(routes::call))
        .route(
            "/api/v2/canister/:canister_id/read_state",
            post(routes::read_state),
        )
        .layer(
            ServiceBuilder::new()
                .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
                .set_x_request_id(MakeRequestUuid)
                .propagate_x_request_id()
                .layer(middleware::from_fn_with_state(
                    state.metric_params.clone(),
                    metrics::with_metrics_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    state.proxier.clone(),
                    routes::preprocess_request,
                )),
        )
        .with_state(state);

    #[cfg(feature = "tls")]
    let routers_http = Router::new()
        .route(
            "/.well-known/acme-challenge/:token",
            get(routes::acme_challenge.layer(Extension(token))),
        )
        .fallback(routes::redirect_to_https);

    // Use HTTPS routers for HTTP if TLS is disabled
    #[cfg(not(feature = "tls"))]
    let routers_http = routers_https;

    // HTTP
    let srvs_http = [Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()]
        .into_iter()
        .map(|ip| {
            Server::bind(SocketAddr::new(ip, cli.http_port))
                .acceptor(DefaultAcceptor)
                .serve(routers_http.clone().into_make_service()) // TODO change back to routers_http - for now routing http==https
        });

    // HTTPS
    #[cfg(feature = "tls")]
    let srvs_https = [Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()]
        .into_iter()
        .map(|ip| {
            Server::bind(SocketAddr::new(ip, cli.https_port))
                .acceptor(tls_acceptor.clone())
                .serve(routers_https.clone().into_make_service())
        });

    // Snapshots
    let snapshot_runner = SnapshotRunner::new(Arc::clone(&routing_table), registry_client);
    let snapshot_runner = WithMetrics(
        snapshot_runner,
        MetricParams::new(&meter, SERVICE_NAME, "run_snapshot"),
    );
    let snapshot_runner = WithThrottle(snapshot_runner, ThrottleParams::new(10 * SECOND));
    let mut snapshot_runner = snapshot_runner;

    // Checks
    let persister = WithMetrics(
        persist::Persister::new(Arc::clone(&lookup_table)),
        MetricParams::new(&meter, SERVICE_NAME, "persist"),
    );

    let checker = Checker::new(Arc::clone(&http_client)); // HTTP client does not need Arc
    let checker = WithMetrics(checker, MetricParams::new(&meter, SERVICE_NAME, "check"));
    let checker = WithRetryLimited(
        checker,
        cli.check_retries,
        Duration::from_secs(cli.check_retry_interval),
    );

    let check_runner = CheckRunner::new(
        Arc::clone(&routing_table),
        cli.min_ok_count,
        cli.max_height_lag,
        persister,
        checker,
    );
    let check_runner = WithMetrics(
        check_runner,
        MetricParams::new(&meter, SERVICE_NAME, "run_check"),
    );
    let check_runner = WithThrottle(
        check_runner,
        ThrottleParams::new(Duration::from_secs(cli.check_interval)),
    );
    let mut check_runner = check_runner;

    // Runners
    let runners: Vec<Box<dyn Run>> = vec![
        Box::new(configuration_runner),
        Box::new(snapshot_runner),
        Box::new(check_runner),
    ];

    TokioScope::scope_and_block(|s| {
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

            Ok::<(), Error>(())
        });

        // Servers
        srvs_http.for_each(|srv| {
            s.spawn(srv.map_err(|err| anyhow!("failed to start http server: {:?}", err)))
        });

        #[cfg(feature = "tls")]
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

#[cfg(feature = "tls")]
async fn prepare_tls(
    cli: &Cli,
) -> Result<(impl Configure, CustomAcceptor, Arc<RwLock<Option<String>>>), Error> {
    // TLS Certificates (Ingress)
    let tls_loader = tls::Loader {
        cert_path: cli.tls_cert_path.clone(),
        pkey_path: cli.tls_pkey_path.clone(),
    };
    let tls_loader = Arc::new(tls_loader);

    // ACME
    let acme_http_client = hyper::Client::builder().build(
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .https_only()
            .enable_all_versions()
            .build(),
    );

    let acme_account = load_or_create_acme_account(
        &cli.acme_credentials_path,    // path
        LetsEncrypt::Production.url(), // acme_provider_url
        Box::new(acme_http_client),    // http_client
    )
    .await
    .context("failed to load acme credentials")?;

    let acme_client = Acme::new(acme_account);

    let acme_order = acme_client.clone();
    let acme_order = Box::new(acme_order);

    let acme_ready = acme_client.clone();
    let acme_ready = Box::new(acme_ready);

    let acme_finalize = acme_client.clone();
    let acme_finalize = WithThrottle(acme_finalize, ThrottleParams::new(Duration::from_secs(5)));
    let acme_finalize = WithRetry(acme_finalize, Duration::from_secs(60));
    let acme_finalize = Box::new(acme_finalize);

    let acme_obtain = acme_client;
    let acme_obtain = WithThrottle(acme_obtain, ThrottleParams::new(Duration::from_secs(5)));
    let acme_obtain = WithRetry(acme_obtain, Duration::from_secs(60));
    let acme_obtain = Box::new(acme_obtain);

    // ACME Token
    let token: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));

    let token_setter = TokenSetter(Arc::clone(&token));
    let token_setter = Box::new(token_setter);

    let tls_provisioner = Provisioner::new(
        token_setter,
        acme_order,
        acme_ready,
        acme_finalize,
        acme_obtain,
    );
    let tls_provisioner = WithStore(tls_provisioner, tls_loader.clone());
    let tls_provisioner = WithLoad(
        tls_provisioner,
        tls_loader.clone(),
        30 * DAY, // Renew if expiration within
    );
    let tls_provisioner = Box::new(tls_provisioner);

    // TLS (Ingress) Configurator
    let tls_acceptor = Arc::new(ArcSwapOption::new(None));

    let tls_configurator = TlsConfigurator::new(tls_acceptor.clone(), tls_provisioner);
    let tls_configurator = WithDeduplication::wrap(tls_configurator);
    let tls_configurator = WithMetrics(
        tls_configurator,
        MetricParams::new(&global::meter(SERVICE_NAME), SERVICE_NAME, "configure_tls"),
    );

    let tls_acceptor = CustomAcceptor::new(tls_acceptor);

    Ok((tls_configurator, tls_acceptor, token))
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

        let MetricParams {
            action,
            counter,
            durationer,
        } = &self.1;

        info!(action, status, duration, error = ?out.as_ref().err());

        out
    }
}

pub struct WithRetryLimited<T>(
    pub T,
    pub u32,      // max_attempts
    pub Duration, // attempt_interval
);

pub struct WithRetry<T>(
    pub T,
    pub Duration, // attempt_interval
);

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

#[cfg(feature = "tls")]
async fn load_or_create_acme_account(
    path: &PathBuf,
    acme_provider_url: &str,
    http_client: Box<dyn instant_acme::HttpClient>,
) -> Result<Account, Error> {
    let f = File::open(path).context("failed to open credentials file for reading");

    // Credentials already exist
    if let Ok(f) = f {
        let creds: AccountCredentials =
            serde_json::from_reader(f).context("failed to json parse existing acme credentials")?;

        let account =
            Account::from_credentials(creds).context("failed to load account from credentials")?;

        return Ok(account);
    }

    // Create new account
    let account = Account::create_with_http(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        acme_provider_url,
        None,
        http_client,
    )
    .await
    .context("failed to create acme account")?;

    // Store credentials
    let f = File::create(path).context("failed to open credentials file for writing")?;

    serde_json::to_writer_pretty(f, &account.credentials())
        .context("failed to serialize acme credentials")?;

    Ok(account)
}

#[cfg(feature = "tls")]
#[cfg(test)]
mod test {
    use anyhow::Error;
    use tempfile::NamedTempFile;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::load_or_create_acme_account;

    struct AcmeProviderGuard(MockServer);

    async fn create_acme_provider() -> Result<(AcmeProviderGuard, String), Error> {
        let mock_server = MockServer::start().await;

        // Directory
        let mock_server_url = mock_server.uri();

        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{
                "newAccount": "{mock_server_url}/new-acct",
                "newNonce": "{mock_server_url}/new-nonce",
                "newOrder": "{mock_server_url}/new-order"
            }}"#,
            )))
            .mount(&mock_server)
            .await;

        // Nonce
        Mock::given(method("HEAD"))
            .and(path("/new-nonce"))
            .respond_with(ResponseTemplate::new(200).append_header(
                "replay-nonce", // key
                "nonce",        // value
            ))
            .mount(&mock_server)
            .await;

        // Account
        Mock::given(method("POST"))
            .and(path("/new-acct"))
            .respond_with(ResponseTemplate::new(200).append_header(
                "Location",   // key
                "account-id", // value
            ))
            .mount(&mock_server)
            .await;

        let acme_provider_url = format!("{}/directory", mock_server_url);

        Ok((
            AcmeProviderGuard(mock_server), // guard
            acme_provider_url,              // acme_provider_url
        ))
    }

    #[tokio::test]
    async fn load_or_create_acme_account_test() -> Result<(), Error> {
        // Spin-up a mocked ACME provider
        let (_guard, acme_provider_url) = create_acme_provider().await?;

        // Get a temporary file path
        let f = NamedTempFile::new()?;
        let p = f.path().to_path_buf();
        drop(f);

        // Create an account
        let account = load_or_create_acme_account(
            &p,                             // path
            &acme_provider_url,             // acme_provider_url
            Box::new(hyper::Client::new()), // http_client
        )
        .await?;

        // Serialize the credentials for later comparison
        let creds = serde_json::to_string(&account.credentials())?;

        // Reload the account
        let account = load_or_create_acme_account(
            &p,                             // path
            &acme_provider_url,             // acme_provider_url
            Box::new(hyper::Client::new()), // http_client
        )
        .await?;

        assert_eq!(
            creds,                                          // previous
            serde_json::to_string(&account.credentials())?, // current
        );

        // Clean up
        std::fs::remove_file(&p)?;

        Ok(())
    }
}
