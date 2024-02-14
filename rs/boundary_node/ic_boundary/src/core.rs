use std::{
    convert::Infallible,
    error::Error as StdError,
    net::{Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_scoped::TokioScope;
use async_trait::async_trait;
use axum::{
    error_handling::HandleErrorLayer,
    middleware,
    response::IntoResponse,
    routing::method_routing::{get, post},
    Router,
};
use axum_extra::middleware::option_layer;
use axum_server::{accept::DefaultAcceptor, Server};
use futures::TryFutureExt;
use ic_interfaces_registry::ZERO_REGISTRY_VERSION;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::{LocalStoreImpl, LocalStoreReader};
use ic_registry_replicator::RegistryReplicator;
use ic_types::CanisterId;
use lazy_static::lazy_static;
use little_loadshedder::{LoadShedError, LoadShedLayer};
use prometheus::Registry;
use regex::Regex;
use rustls::cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384};
use tokio::sync::RwLock;
use tower::{limit::ConcurrencyLimitLayer, ServiceBuilder};
use tower_http::{compression::CompressionLayer, request_id::MakeRequestUuid, ServiceBuilderExt};
use tracing::{info, warn};

use crate::{
    cache::{cache_middleware, Cache},
    check::{Checker, Runner as CheckRunner},
    cli::Cli,
    dns::DnsResolver,
    firewall::{FirewallGenerator, SystemdReloader},
    http::{HttpClient, ReqwestClient},
    management,
    metrics::{
        self, HttpMetricParams, HttpMetricParamsStatus, MetricParams, MetricParamsCheck,
        MetricParamsPersist, MetricParamsSnapshot, MetricsCache, MetricsRunner, WithMetrics,
        WithMetricsCheck, WithMetricsPersist, WithMetricsSnapshot,
    },
    persist::{Persister, Routes},
    rate_limiting::RateLimit,
    retry::{retry_request, RetryParams},
    routes::{self, ErrorCause, Health, Lookup, Proxy, ProxyRouter, RootKey},
    snapshot::{RegistrySnapshot, SnapshotPersister, Snapshotter},
    tls_verify::TlsVerifier,
};

#[cfg(not(feature = "tls"))]
use {hyperlocal::UnixServerExt, std::os::unix::fs::PermissionsExt};

#[cfg(feature = "tls")]
use {
    crate::{
        acme::Acme,
        configuration::{ConfigurationRunner, Configurator, TlsConfigurator},
        tls::{
            acme_challenge, load_or_create_acme_account, redirect_to_https, CustomAcceptor,
            Loader as TlsLoader, Provisioner, TokenOwner, WithLoad, WithStore,
        },
    },
    instant_acme::LetsEncrypt,
};

pub const SERVICE_NAME: &str = "ic_boundary";
pub const AUTHOR_NAME: &str = "Boundary Node Team <boundary-nodes@dfinity.org>";
const SYSTEMCTL_BIN: &str = "/usr/bin/systemctl";

const SECOND: Duration = Duration::from_secs(1);
#[cfg(feature = "tls")]
const DAY: Duration = Duration::from_secs(24 * 3600);

const KB: usize = 1024;
const MB: usize = 1024 * KB;

pub const MAX_REQUEST_BODY_SIZE: usize = 4 * MB;
const METRICS_CACHE_CAPACITY: usize = 15 * MB;

pub const MANAGEMENT_CANISTER_ID_PRINCIPAL: CanisterId = CanisterId::ic_00();

lazy_static! {
    pub static ref HOSTNAME_REGEX: Regex =
        Regex::new(r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$").unwrap();
}

pub async fn main(cli: Cli) -> Result<(), Error> {
    // Metrics
    let metrics_registry: Registry = Registry::new_custom(Some(SERVICE_NAME.into()), None)?;

    info!(
        msg = format!("Starting {SERVICE_NAME}"),
        metrics_addr = cli.monitoring.metrics_addr.to_string().as_str(),
    );

    let routing_table = Arc::new(ArcSwapOption::empty());
    let registry_snapshot = Arc::new(ArcSwapOption::empty());

    // DNS
    let dns_resolver = DnsResolver::new(Arc::clone(&registry_snapshot));

    // TLS Verification
    let tls_verifier = TlsVerifier::new(Arc::clone(&registry_snapshot));

    // TLS Configuration
    let rustls_config = rustls::ClientConfig::builder()
        .with_cipher_suites(&[TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256])
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("unable to build Rustls config")?
        .with_custom_certificate_verifier(Arc::new(tls_verifier))
        .with_no_client_auth();

    let keepalive = Duration::from_secs(cli.listen.http_keepalive);

    // HTTP Client
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(cli.listen.http_timeout))
        .connect_timeout(Duration::from_millis(cli.listen.http_timeout_connect))
        .pool_idle_timeout(Some(Duration::from_secs(cli.listen.http_idle_timeout))) // After this duration the idle connection is closed (default 90s)
        .http2_keep_alive_interval(Some(keepalive)) // Keepalive interval for http2 connections
        .http2_keep_alive_timeout(Duration::from_secs(cli.listen.http_keepalive_timeout)) // Close connection if no reply after timeout
        .http2_keep_alive_while_idle(true) // Also ping connections that have no streams open
        .tcp_keepalive(Some(keepalive)) // Enable TCP keepalives
        .user_agent(SERVICE_NAME)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .use_preconfigured_tls(rustls_config)
        .dns_resolver(Arc::new(dns_resolver))
        .build()
        .context("unable to build HTTP client")?;
    let http_client = Arc::new(ReqwestClient(http_client));

    // Registry Client
    let local_store = Arc::new(LocalStoreImpl::new(&cli.registry.local_store_path));

    let registry_client = Arc::new(RegistryClientImpl::new(
        local_store.clone(), // data_provider
        None,                // metrics_registry
    ));

    registry_client
        .fetch_and_start_polling()
        .context("failed to start registry client")?;

    #[cfg(feature = "tls")]
    let (configuration_runner, tls_acceptor, token_owner) = prepare_tls(&cli, &metrics_registry)
        .await
        .context("unable to prepare TLS")?;

    // Caching
    let cache = cli.cache.cache_size_bytes.map(|x| {
        Arc::new(
            Cache::new(
                x,
                cli.cache.cache_max_item_size_bytes,
                Duration::from_secs(cli.cache.cache_ttl_seconds),
                cli.cache.cache_non_anonymous,
            )
            .expect("unable to initialize cache"),
        )
    });

    // Server / API
    let routers_https = setup_router(
        registry_snapshot.clone(),
        routing_table.clone(),
        http_client.clone(),
        &cli,
        &metrics_registry,
        cache.clone(),
    );

    #[cfg(feature = "tls")]
    let routers_http = Router::new()
        .route(
            "/.well-known/acme-challenge/:token",
            get(acme_challenge).with_state(token_owner),
        )
        .fallback(redirect_to_https);

    // Use HTTPS routers for HTTP if TLS is disabled
    #[cfg(not(feature = "tls"))]
    let routers_http = routers_https;

    // HTTP
    let srvs_http = cli.listen.http_port.map(|x| {
        Server::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), x))
            .acceptor(DefaultAcceptor)
            .serve(
                routers_http
                    .clone()
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
    });

    // HTTP Unix Socket
    #[cfg(not(feature = "tls"))]
    let srvs_http_unix = cli.listen.http_unix_socket.map(|x| {
        // Remove the socket file if it's there
        if x.exists() {
            std::fs::remove_file(&x).expect("unable to remove socket");
        }

        let srv = hyper::Server::bind_unix(&x)
            .expect("cannot bind to the socket")
            .serve(routers_http.clone().into_make_service());

        std::fs::set_permissions(&x, std::fs::Permissions::from_mode(0o666))
            .expect("unable to set permissions on socket");

        srv
    });

    #[cfg(not(feature = "tls"))]
    if srvs_http.is_none() && srvs_http_unix.is_none() {
        panic!("at least one of --http-port or --http-unix-socket must be specified");
    }

    // HTTPS
    #[cfg(feature = "tls")]
    let srvs_https = Server::bind(SocketAddr::new(
        Ipv6Addr::UNSPECIFIED.into(),
        cli.listen.https_port,
    ))
    .acceptor(tls_acceptor.clone())
    .serve(
        routers_https
            .clone()
            .into_make_service_with_connect_info::<SocketAddr>(),
    );

    // Metrics
    let metrics_cache = Arc::new(RwLock::new(MetricsCache::new(METRICS_CACHE_CAPACITY)));

    let metrics_router = Router::new()
        .route("/metrics", get(metrics::metrics_handler))
        .layer(
            CompressionLayer::new()
                .gzip(true)
                .br(true)
                .zstd(true)
                .deflate(true),
        )
        .with_state(metrics::MetricsHandlerArgs {
            cache: metrics_cache.clone(),
        });

    let metrics_runner = WithThrottle(
        WithMetrics(
            MetricsRunner::new(
                metrics_cache,
                metrics_registry.clone(),
                cache,
                Arc::clone(&registry_snapshot),
            ),
            MetricParams::new(&metrics_registry, "run_metrics"),
        ),
        ThrottleParams::new(5 * SECOND),
    );

    // Snapshots
    let snapshot_runner = WithMetricsSnapshot(
        {
            let mut snapshotter = Snapshotter::new(
                Arc::clone(&registry_snapshot),
                registry_client.clone(),
                Duration::from_secs(cli.registry.min_version_age),
            );

            if let Some(v) = &cli.firewall.nftables_system_replicas_path {
                let fw_reloader = SystemdReloader::new(SYSTEMCTL_BIN.into(), "nftables", "reload");

                let fw_generator = FirewallGenerator::new(
                    v.clone(),
                    cli.firewall.nftables_system_replicas_var.clone(),
                );

                let persister = SnapshotPersister::new(fw_generator, fw_reloader);
                snapshotter.set_persister(persister);
            }

            snapshotter
        },
        MetricParamsSnapshot::new(&metrics_registry),
    );

    let snapshot_runner = WithThrottle(snapshot_runner, ThrottleParams::new(5 * SECOND));

    // Checks
    let persister = WithMetricsPersist(
        Persister::new(Arc::clone(&routing_table)),
        MetricParamsPersist::new(&metrics_registry),
    );

    let checker = Checker::new(http_client, Duration::from_millis(cli.health.check_timeout));
    let checker = WithMetricsCheck(checker, MetricParamsCheck::new(&metrics_registry));
    let checker = WithRetryLimited(checker, cli.health.check_retries, Duration::ZERO);

    let check_runner = CheckRunner::new(
        Arc::clone(&registry_snapshot),
        cli.health.min_ok_count,
        cli.health.max_height_lag,
        persister,
        checker,
    );
    let check_runner = WithMetrics(
        check_runner,
        MetricParams::new(&metrics_registry, "run_check"),
    );
    let check_runner = WithThrottle(
        check_runner,
        ThrottleParams::new(Duration::from_millis(cli.health.check_interval)),
    );

    // Runners
    let runners: Vec<Box<dyn Run>> = vec![
        #[cfg(feature = "tls")]
        Box::new(configuration_runner),
        Box::new(snapshot_runner),
        Box::new(check_runner),
        Box::new(metrics_runner),
    ];

    let (registry_replicator, nns_pub_key) = if !cli.registry.disable_registry_replicator {
        // Check if we require an NNS key
        let nns_pub_key = {
            // Check if the local store is initialized
            if !local_store
                .get_changelog_since_version(ZERO_REGISTRY_VERSION)
                .expect("failed to read registry local store")
                .is_empty()
            {
                None
            } else {
                // If it's not - then we need an NNS public key to initialize it
                let nns_pub_key_path = cli
                    .registry
                    .nns_pub_key_pem
                    .expect("NNS public key is required to init Registry local store");

                Some(
                    ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key(&nns_pub_key_path)
                        .expect("failed to parse NNS public key"),
                )
            }
        };

        // Notice no-op logger
        let logger = ic_logger::new_replica_logger(
            slog::Logger::root(tracing_slog::TracingSlogDrain, slog::o!()), // logger
            &ic_config::logger::Config::default(),                          // config
        );

        (
            Some(RegistryReplicator::new_with_clients(
                logger,
                local_store,
                registry_client,
                Duration::from_millis(cli.registry.nns_poll_interval_ms), // poll_delay
            )),
            nns_pub_key,
        )
    } else {
        (None, None)
    };

    TokioScope::scope_and_block(|s| {
        s.spawn(
            axum::Server::bind(&cli.monitoring.metrics_addr)
                .serve(metrics_router.into_make_service())
                .map_err(|err| anyhow!("server failed: {:?}", err)),
        );

        if let Some(v) = registry_replicator {
            s.spawn(async move {
                v.start_polling(cli.registry.nns_urls, nns_pub_key)
                    .await
                    .context("failed to start registry replicator")?
                    .await
                    .context("registry replicator failed")?;

                Ok::<(), Error>(())
            });
        }

        // Servers
        if let Some(v) = srvs_http {
            s.spawn(v.map_err(|err| anyhow!("failed to start http server: {:?}", err)));
        }

        #[cfg(not(feature = "tls"))]
        if let Some(v) = srvs_http_unix {
            s.spawn(v.map_err(|err| anyhow!("failed to start http unix socket server: {:?}", err)));
        }

        #[cfg(feature = "tls")]
        s.spawn(srvs_https.map_err(|err| anyhow!("failed to start https server: {:?}", err)));

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

// Load shedding middleware is fallible, so we must handle the errors that it emits and convert them into responses.
// Error argument will always be LoadShedError::Overload since the inner Axum layers are infallible, so we don't care for it.
async fn handle_shed_error(_err: LoadShedError<Infallible>) -> impl IntoResponse {
    ErrorCause::LoadShed
}

pub fn setup_router(
    registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    routing_table: Arc<ArcSwapOption<Routes>>,
    http_client: Arc<dyn HttpClient>,
    cli: &Cli,
    metrics_registry: &Registry,
    cache: Option<Arc<Cache>>,
) -> Router {
    let proxy_router = ProxyRouter::new(
        http_client.clone(),
        Arc::clone(&routing_table),
        Arc::clone(&registry_snapshot),
    );

    let proxy_router = Arc::new(proxy_router);

    let (proxy, lookup, root_key, health) = (
        proxy_router.clone() as Arc<dyn Proxy>,
        proxy_router.clone() as Arc<dyn Lookup>,
        proxy_router.clone() as Arc<dyn RootKey>,
        proxy_router.clone() as Arc<dyn Health>,
    );

    let query_route = Router::new()
        .route(routes::PATH_QUERY, {
            post(routes::handle_call).with_state(proxy.clone())
        })
        .layer(option_layer(cache.map(|x| {
            middleware::from_fn_with_state(x.clone(), cache_middleware)
        })));

    let call_route = {
        let mut route = Router::new().route(routes::PATH_CALL, {
            post(routes::handle_call).with_state(proxy.clone())
        });

        // will panic if ip_rate_limit is Some(0)
        if let Some(rl) = cli.rate_limiting.rate_limit_per_second_per_ip {
            route = RateLimit::try_from(rl).unwrap().add_ip_rate_limiting(route);
        }

        // will panic if subnet_rate_limit is Some(0)
        if let Some(rl) = cli.rate_limiting.rate_limit_per_second_per_subnet {
            route = RateLimit::try_from(rl)
                .unwrap()
                .add_subnet_rate_limiting(route)
        }

        route
    };

    let read_state_route = Router::new().route(routes::PATH_READ_STATE, {
        post(routes::handle_call).with_state(proxy.clone())
    });

    let status_route = Router::new()
        .route(routes::PATH_STATUS, {
            get(routes::status).with_state((root_key.clone(), health.clone()))
        })
        .layer(middleware::from_fn_with_state(
            HttpMetricParamsStatus::new(metrics_registry),
            metrics::metrics_middleware_status,
        ));

    let health_route = Router::new().route(routes::PATH_HEALTH, {
        get(routes::health).with_state(health.clone())
    });

    let proxy_routes = query_route.merge(call_route).merge(read_state_route).layer(
        // Layers under ServiceBuilder are executed top-down (opposite to that under Router)
        // 1st layer wraps 2nd layer and so on
        ServiceBuilder::new()
            .layer(middleware::from_fn(routes::validate_request))
            .set_x_request_id(MakeRequestUuid)
            .layer(option_layer(
                (!cli.monitoring.disable_request_logging).then_some(
                    middleware::from_fn_with_state(
                        HttpMetricParams::new(
                            metrics_registry,
                            "http_request_in",
                            cli.monitoring.log_failed_requests_only,
                        ),
                        metrics::metrics_middleware,
                    ),
                ),
            ))
            .layer(option_layer(
                cli.listen.max_concurrency.map(ConcurrencyLimitLayer::new),
            ))
            .layer(option_layer(cli.listen.shed_ewma_param.map(|x| {
                if !(0.0..=1.0).contains(&x) {
                    panic!("Shed EWMA param must be in range 0.0..1.0");
                }

                if cli.listen.shed_target_latency == 0 {
                    panic!("Shed taget latency should be > 0");
                }

                warn!(
                    "Load shedding enabled: EWMA param {}, target latency {}ms",
                    x, cli.listen.shed_target_latency
                );

                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(handle_shed_error))
                    .layer(LoadShedLayer::new(
                        x,
                        Duration::from_millis(cli.listen.shed_target_latency),
                    ))
            })))
            .layer(middleware::from_fn(routes::postprocess_response))
            .layer(middleware::from_fn(routes::preprocess_request))
            .layer(middleware::from_fn(management::btc_mw))
            .layer(option_layer(
                cli.rate_limiting.rate_limit_ledger_transfer.map(|x| {
                    middleware::from_fn_with_state(
                        Arc::new(management::LedgerRatelimitState::new(x)),
                        management::ledger_ratelimit_transfer_mw,
                    )
                }),
            ))
            .layer(middleware::from_fn_with_state(
                lookup.clone(),
                routes::lookup_subnet,
            ))
            .layer(middleware::from_fn_with_state(
                RetryParams {
                    retry_count: cli.retry.retry_count as usize,
                    retry_update_call: cli.retry.retry_update_call,
                },
                retry_request,
            )),
    );

    proxy_routes.merge(status_route).merge(health_route)
}

#[cfg(feature = "tls")]
async fn prepare_tls(
    cli: &Cli,
    registry: &Registry,
) -> Result<(impl Run, CustomAcceptor, Arc<TokenOwner>), Error> {
    if !HOSTNAME_REGEX.is_match(&cli.tls.hostname) {
        return Err(anyhow!(
            "'{}' does not look like a valid hostname",
            cli.tls.hostname
        ));
    }

    // TLS Certificates (Ingress)
    let tls_loader = TlsLoader {
        cert_path: cli.tls.tls_cert_path.clone(),
        pkey_path: cli.tls.tls_pkey_path.clone(),
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
        &cli.tls.acme_credentials_path, // path
        LetsEncrypt::Production.url(),  // acme_provider_url
        Box::new(acme_http_client),     // http_client
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

    // ACME Token owner
    let token_owner = Arc::new(TokenOwner::new());

    let tls_provisioner = Provisioner::new(
        Arc::clone(&token_owner),
        acme_order,
        acme_ready,
        acme_finalize,
        acme_obtain,
    );
    let tls_provisioner = WithStore(tls_provisioner, tls_loader.clone());
    let tls_provisioner = WithLoad(
        tls_provisioner,
        tls_loader.clone(),
        cli.tls.renew_days_before * DAY, // Renew if expiration within
    );
    let tls_provisioner = Box::new(tls_provisioner);

    // TLS (Ingress) Configurator
    let tls_acceptor = Arc::new(ArcSwapOption::new(None));

    let tls_configurator = TlsConfigurator::new(tls_acceptor.clone(), tls_provisioner);
    let tls_configurator = WithMetrics(
        tls_configurator,
        MetricParams::new(registry, "configure_tls"),
    );

    let tls_acceptor = CustomAcceptor::new(tls_acceptor);

    // Service Configurator
    let svc_configurator = Configurator {
        tls: Box::new(tls_configurator),
    };

    // Configuration
    let configuration_runner = ConfigurationRunner::new(
        cli.tls.hostname.clone(),
        svc_configurator, // configurator
    );
    let configuration_runner = WithMetrics(
        configuration_runner,
        MetricParams::new(registry, "run_configuration"),
    );
    let configuration_runner =
        WithThrottle(configuration_runner, ThrottleParams::new(600 * SECOND));

    Ok((configuration_runner, tls_acceptor, token_owner))
}

#[async_trait]
pub trait Run: Send + Sync {
    async fn run(&mut self) -> Result<(), Error>;
}

#[async_trait]
impl<T: Run> Run for WithMetrics<T> {
    async fn run(&mut self) -> Result<(), Error> {
        let start_time = Instant::now();
        let out = self.0.run().await;
        let duration = start_time.elapsed().as_secs_f64();
        let status = if out.is_ok() { "ok" } else { "fail" };

        let MetricParams {
            action,
            counter,
            recorder,
        } = &self.1;

        counter.with_label_values(&[status]).inc();
        recorder.with_label_values(&[status]).observe(duration);

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

pub struct ThrottleParams {
    pub throttle_duration: Duration,
    pub next_time: Option<Instant>,
}

impl ThrottleParams {
    fn new(throttle_duration: Duration) -> Self {
        Self {
            throttle_duration,
            next_time: None,
        }
    }
}

pub struct WithThrottle<T>(pub T, pub ThrottleParams);

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

// Process error chain trying to find given error type
pub fn error_source<E: StdError + 'static>(error: &impl StdError) -> Option<&E> {
    let mut source = error.source();
    while let Some(err) = source {
        if let Some(v) = err.downcast_ref() {
            return Some(v);
        }

        source = err.source();
    }

    None
}
