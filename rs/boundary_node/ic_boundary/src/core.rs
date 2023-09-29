use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_scoped::TokioScope;
use async_trait::async_trait;
use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::method_routing::{get, post},
    Router,
};
use axum_server::{accept::DefaultAcceptor, Server};
use futures::TryFutureExt;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::LocalStoreImpl;
use ic_registry_replicator::RegistryReplicator;
use prometheus::{labels, Registry};
use tower::ServiceBuilder;
use tower_http::{request_id::MakeRequestUuid, ServiceBuilderExt};
use tracing::info;

#[cfg(feature = "tls")]
use {
    axum::{handler::Handler, Extension},
    instant_acme::LetsEncrypt,
    tokio::sync::RwLock,
};

use crate::{
    cache::{cache_middleware, Cache},
    check::{Checker, Runner as CheckRunner},
    cli::Cli,
    configuration::{
        Configurator, Configure, FirewallConfigurator, ServiceConfiguration, TlsConfigurator,
        WithDeduplication,
    },
    dns::DnsResolver,
    http::ReqwestClient,
    metrics::{self, HttpMetricParams, MetricParams, WithMetrics, HTTP_DURATION_BUCKETS},
    nns::{Load, Loader},
    persist,
    rate_limiting::RateLimit,
    routes::{self, Health, Lookup, Proxy, ProxyRouter, RootKey},
    snapshot::Runner as SnapshotRunner,
    tls_verify::TlsVerifier,
};

#[cfg(feature = "tls")]
use crate::{
    acme::Acme,
    tls::{
        load_or_create_acme_account, CustomAcceptor, Loader as TlsLoader, Provisioner, TokenSetter,
        WithLoad, WithStore,
    },
};

pub const SERVICE_NAME: &str = "ic_boundary";
pub const AUTHOR_NAME: &str = "Boundary Node Team <boundary-nodes@dfinity.org>";
const DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";

const SECOND: Duration = Duration::from_secs(1);
#[cfg(feature = "tls")]
const DAY: Duration = Duration::from_secs(24 * 3600);

const KB: usize = 1024;
const MB: usize = 1024 * KB;

pub async fn main(cli: Cli) -> Result<(), Error> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .finish(),
    )?;

    // Metrics
    let registry: Registry = Registry::new_custom(
        Some(SERVICE_NAME.into()),
        Some(labels! {
            "service".into() => SERVICE_NAME.into(),
        }),
    )?;

    let metrics_router = Router::new()
        .route("/metrics", get(metrics::metrics_handler))
        .with_state(metrics::MetricsHandlerArgs {
            registry: registry.clone(),
        });

    info!(
        msg = format!("Starting {SERVICE_NAME}"),
        metrics_addr = cli.monitoring.metrics_addr.to_string().as_str(),
    );

    let lookup_table = Arc::new(ArcSwapOption::empty());
    let routing_table = Arc::new(ArcSwapOption::empty());

    // DNS
    let dns_resolver = DnsResolver::new(Arc::clone(&routing_table));
    let dns_resolver = WithMetrics(
        dns_resolver,
        MetricParams::new_with_opts(
            &registry,
            "dns_resolve",
            &["status", "server_name"],
            Some(&[0.0001, 0.0005, 0.001]),
        ),
    );

    // TLS Verification
    let tls_verifier = TlsVerifier::new(Arc::clone(&routing_table));
    let tls_verifier = WithMetrics(
        tls_verifier,
        MetricParams::new_with_opts(
            &registry,
            "verify_tls",
            &["status", "server_name"],
            Some(&[0.0001, 0.0005, 0.001]),
        ),
    );

    // TLS Configuration
    let rustls_config = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("unable to build Rustls config")?
        .with_custom_certificate_verifier(Arc::new(tls_verifier))
        .with_no_client_auth();

    // HTTP Client
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cli.listen.http_timeout))
        .connect_timeout(Duration::from_secs(cli.listen.http_timeout_connect))
        .use_preconfigured_tls(rustls_config)
        .dns_resolver(Arc::new(dns_resolver))
        .build()
        .context("unable to build HTTP client")?;

    let http_client = ReqwestClient(http_client);
    let http_client = WithMetrics(
        http_client,
        MetricParams::new_with_opts(
            &registry,
            "http_request_out",
            &["status", "method", "scheme", "host", "status_code"],
            Some(HTTP_DURATION_BUCKETS),
        ),
    );
    let http_client = Arc::new(http_client);

    // Registry Client
    let local_store = Arc::new(LocalStoreImpl::new(&cli.registry.local_store_path));

    let registry_client = Arc::new(RegistryClientImpl::new(
        local_store.clone(), // data_provider
        None,                // metrics_registry
    ));

    registry_client
        .fetch_and_start_polling()
        .context("failed to start registry client")?;

    let nns_pub_key =
        ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key(&cli.registry.nns_pub_key_pem)
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
            Duration::from_millis(cli.registry.nns_poll_interval_ms), // poll_delay
        )
    };

    #[cfg(feature = "tls")]
    let (tls_configurator, tls_acceptor, token) = prepare_tls(&cli, &registry)
        .await
        .context("unable to prepare TLS")?;

    // No-op configurator is used to make compiler/clippy happy
    // Otherwise the enums in Configurator become single-variant and it complains
    #[cfg(not(feature = "tls"))]
    let tls_configurator = TlsConfigurator {};

    // Firewall Configuration
    let fw_configurator = FirewallConfigurator {};
    let fw_configurator = WithDeduplication::wrap(fw_configurator);
    let fw_configurator = WithMetrics(
        fw_configurator,
        MetricParams::new(&registry, "configure_firewall"),
    );

    // Service Configurator
    let svc_configurator = Configurator {
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
        MetricParams::new(&registry, "run_configuration"),
    );
    let configuration_runner = WithThrottle(configuration_runner, ThrottleParams::new(10 * SECOND));

    // Server / API
    let proxy_router = ProxyRouter::new(
        http_client.clone(),
        Arc::clone(&lookup_table),
        [DER_PREFIX.as_slice(), nns_pub_key.into_bytes().as_slice()].concat(),
    );

    let proxy_router = Arc::new(proxy_router);

    let (p, lk, rk, h) = (
        proxy_router.clone() as Arc<dyn Proxy>,
        proxy_router.clone() as Arc<dyn Lookup>,
        proxy_router.clone() as Arc<dyn RootKey>,
        proxy_router.clone() as Arc<dyn Health>,
    );

    let routers_https = {
        let query_route = {
            let mut route = Router::new().route(routes::PATH_QUERY, {
                post(routes::handle_call).with_state(p.clone())
            });

            // Setup caching if configured
            if let Some(cache_size) = cli.cache.cache_size_bytes {
                let cache = Cache::new(
                    cache_size,
                    cli.cache.cache_max_item_size_bytes,
                    Duration::from_secs(cli.cache.cache_ttl_seconds),
                    cli.cache.cache_non_anonymous,
                );

                let cache = Arc::new(cache);

                route = route.layer(middleware::from_fn_with_state(
                    Arc::clone(&cache),
                    cache_middleware,
                ));
            }

            route
        };

        let call_route = {
            let mut route = Router::new().route(routes::PATH_CALL, {
                post(routes::handle_call).with_state(p.clone())
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
            post(routes::handle_call).with_state(p.clone())
        });

        let status_route = Router::new().route(routes::PATH_STATUS, {
            get(routes::status).with_state((rk.clone(), h.clone()))
        });

        query_route
            .merge(call_route)
            .merge(read_state_route)
            .merge(status_route)
            .layer(
                ServiceBuilder::new()
                    .set_x_request_id(MakeRequestUuid)
                    .propagate_x_request_id()
                    .layer(DefaultBodyLimit::max(2 * MB))
                    .layer(middleware::from_fn_with_state(
                        HttpMetricParams::new(&registry, "http_request_in"),
                        metrics::with_metrics_middleware,
                    ))
                    .layer(middleware::from_fn_with_state(
                        lk.clone(),
                        routes::preprocess_request,
                    ))
                    .layer(middleware::from_fn(routes::postprocess_response)),
            )
    };

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
            Server::bind(SocketAddr::new(ip, cli.listen.http_port))
                .acceptor(DefaultAcceptor)
                .serve(routers_http.clone().into_make_service()) // TODO change back to routers_http - for now routing http==https
        });

    // HTTPS
    #[cfg(feature = "tls")]
    let srvs_https = [Ipv4Addr::UNSPECIFIED.into(), Ipv6Addr::UNSPECIFIED.into()]
        .into_iter()
        .map(|ip| {
            Server::bind(SocketAddr::new(ip, cli.listen.https_port))
                .acceptor(tls_acceptor.clone())
                .serve(routers_https.clone().into_make_service())
        });

    // Snapshots
    let snapshot_runner = SnapshotRunner::new(Arc::clone(&routing_table), registry_client);
    let snapshot_runner = WithMetrics(
        snapshot_runner,
        MetricParams::new(&registry, "run_snapshot"),
    );
    let snapshot_runner = WithThrottle(snapshot_runner, ThrottleParams::new(10 * SECOND));

    // Checks
    let persister = WithMetrics(
        persist::Persister::new(Arc::clone(&lookup_table)),
        MetricParams::new(&registry, "persist"),
    );

    let checker = Checker::new(http_client);
    let checker = WithMetrics(
        checker,
        MetricParams::new_with_opts(
            &registry,
            "check",
            &["status", "node_id", "subnet_id", "addr"],
            Some(HTTP_DURATION_BUCKETS),
        ),
    );
    let checker = WithRetryLimited(
        checker,
        cli.health.check_retries,
        Duration::from_secs(cli.health.check_retry_interval),
    );

    let check_runner = CheckRunner::new(
        Arc::clone(&routing_table),
        cli.health.min_ok_count,
        cli.health.max_height_lag,
        persister,
        checker,
    );
    let check_runner = WithMetrics(check_runner, MetricParams::new(&registry, "run_check"));
    let check_runner = WithThrottle(
        check_runner,
        ThrottleParams::new(Duration::from_secs(cli.health.check_interval)),
    );

    // Runners
    let runners: Vec<Box<dyn Run>> = vec![
        Box::new(configuration_runner),
        Box::new(snapshot_runner),
        Box::new(check_runner),
    ];

    TokioScope::scope_and_block(|s| {
        s.spawn(
            axum::Server::bind(&cli.monitoring.metrics_addr)
                .serve(metrics_router.into_make_service())
                .map_err(|err| anyhow!("server failed: {:?}", err)),
        );

        s.spawn(async move {
            registry_replicator
                .start_polling(cli.registry.nns_urls, Some(nns_pub_key))
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
    registry: &Registry,
) -> Result<(impl Configure, CustomAcceptor, Arc<RwLock<Option<String>>>), Error> {
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
        MetricParams::new(registry, "configure_tls"),
    );

    let tls_acceptor = CustomAcceptor::new(tls_acceptor);

    Ok((tls_configurator, tls_acceptor, token))
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
