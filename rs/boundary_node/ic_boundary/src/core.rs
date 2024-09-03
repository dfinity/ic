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
use candid::DecoderConfig;
use futures::TryFutureExt;
use ic_bn_lib::http;
use ic_interfaces_registry::ZERO_REGISTRY_VERSION;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::{LocalStoreImpl, LocalStoreReader};
use ic_registry_replicator::RegistryReplicator;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use little_loadshedder::{LoadShedError, LoadShedLayer};
use nix::unistd::{getpgid, setpgid, Pid};
use prometheus::Registry;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tower::{limit::ConcurrencyLimitLayer, ServiceBuilder};
use tower_http::{compression::CompressionLayer, request_id::MakeRequestUuid, ServiceBuilderExt};
use tracing::{debug, error, warn};

use crate::{
    bouncer,
    cache::{cache_middleware, Cache},
    check::{Checker, Runner as CheckRunner},
    cli::Cli,
    dns::DnsResolver,
    firewall::{FirewallGenerator, SystemdReloader},
    geoip,
    metrics::{
        self, HttpMetricParams, HttpMetricParamsStatus, MetricParams, MetricParamsCheck,
        MetricParamsPersist, MetricParamsSnapshot, MetricsCache, MetricsRunner, WithMetrics,
        WithMetricsCheck, WithMetricsPersist, WithMetricsSnapshot, HTTP_DURATION_BUCKETS,
    },
    persist::{Persist, Persister, Routes},
    rate_limiting::{generic, RateLimit},
    retry::{retry_request, RetryParams},
    routes::{self, ErrorCause, Health, Lookup, Proxy, ProxyRouter, RootKey},
    snapshot::{
        generate_stub_snapshot, generate_stub_subnet, RegistrySnapshot, SnapshotPersister,
        Snapshotter,
    },
    tls_verify::TlsVerifier,
};

#[cfg(feature = "tls")]
use {crate::cli, rustls::server::ResolvesServerCert};

pub const SERVICE_NAME: &str = "ic_boundary";
pub const AUTHOR_NAME: &str = "Boundary Node Team <boundary-nodes@dfinity.org>";
const SYSTEMCTL_BIN: &str = "/usr/bin/systemctl";

pub const SECOND: Duration = Duration::from_secs(1);

const KB: usize = 1024;
const MB: usize = 1024 * KB;

pub const MAX_REQUEST_BODY_SIZE: usize = 4 * MB;
const METRICS_CACHE_CAPACITY: usize = 15 * MB;

/// Limit the amount of work for skipping unneeded data on the wire when parsing Candid.
/// The value of 10_000 follows the Candid recommendation.
const DEFAULT_SKIPPING_QUOTA: usize = 10_000;

pub fn decoder_config() -> DecoderConfig {
    let mut config = DecoderConfig::new();
    config.set_skipping_quota(DEFAULT_SKIPPING_QUOTA);
    config.set_full_error_message(false);
    config
}

pub async fn main(cli: Cli) -> Result<(), Error> {
    if cli.listen.http_timeout_connect > cli.health.check_timeout {
        panic!("--check-timeout should be longer than --http-timeout-connect");
    }

    if !(cli.registry.local_store_path.is_none() ^ cli.registry.stub_replica.is_empty()) {
        panic!("--local-store-path and --stub-replica are mutually exclusive and at least one of them must be specified");
    }

    // make sure ic-boundary is the leader of its own process group
    let pgid = getpgid(None).context("Failed to get the process group ID.")?;
    if pgid != Pid::this() {
        // If that is not the case, set it as the leader of its own process group
        setpgid(Pid::from_raw(0), Pid::from_raw(0))
            .context("Failed to setup a new process group for ic-boundary.")?;
    }

    // Install crypto-provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("unable to install Rustls crypto provider"))?;

    // Metrics
    let metrics_registry = Registry::new_custom(Some(SERVICE_NAME.into()), None)?;

    warn!(
        msg = format!("Starting {SERVICE_NAME}"),
        metrics_addr = cli.monitoring.metrics_addr.to_string().as_str(),
    );

    let routing_table = Arc::new(ArcSwapOption::empty());
    let registry_snapshot = Arc::new(ArcSwapOption::empty());

    // DNS
    let dns_resolver = DnsResolver::new(Arc::clone(&registry_snapshot));

    // TLS client
    let tls_verifier = Arc::new(TlsVerifier::new(
        Arc::clone(&registry_snapshot),
        cli.listen.skip_replica_tls_verification,
    ));

    let mut tls_config_client =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous() // Nothing really dangerous here
            .with_custom_certificate_verifier(tls_verifier)
            .with_no_client_auth();

    // Enable ALPN to negotiate HTTP version
    let mut alpn = vec![];
    if !cli.listen.disable_http2_client {
        alpn.push(b"h2".to_vec());
    }
    alpn.push(b"http/1.1".to_vec());
    tls_config_client.alpn_protocols = alpn;

    // Set larger session resumption cache to accomodate all replicas (256 by default)
    tls_config_client.resumption = rustls::client::Resumption::in_memory_sessions(
        4096 * cli.listen.http_client_count as usize,
    );

    let http_client_opts = http::client::Options {
        timeout_connect: Duration::from_millis(cli.listen.http_timeout_connect),
        timeout_read: Duration::from_secs(15),
        timeout: Duration::from_millis(cli.listen.http_timeout),
        tcp_keepalive: Some(Duration::from_secs(cli.listen.http_keepalive)),
        http2_keepalive: Some(Duration::from_secs(cli.listen.http_keepalive_timeout)),
        http2_keepalive_timeout: Duration::from_secs(cli.listen.http_keepalive),
        user_agent: SERVICE_NAME.into(),
        tls_config: Some(tls_config_client),
        dns_resolver: Some(dns_resolver),
    };

    let http_client = http::client::ReqwestClientRoundRobin::new(
        http_client_opts,
        cli.listen.http_client_count as usize,
    )?;
    let http_client = WithMetrics(
        http_client,
        MetricParams::new_with_opts(
            &metrics_registry,
            "http_client",
            &["success", "status", "http_ver"],
            Some(HTTP_DURATION_BUCKETS),
        ),
    );
    let http_client = Arc::new(http_client);

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

    // Bouncer
    let bouncer = if cli.bouncer.bouncer_enable {
        Some(bouncer::setup(&cli.bouncer, &metrics_registry).context("unable to setup bouncer")?)
    } else {
        None
    };

    // Generic Ratelimiter
    let generic_limiter = Arc::new(generic::Limiter::new(
        cli.rate_limiting.rate_limit_generic.clone(),
    ));

    // Prepare Axum Router
    let router = setup_router(
        registry_snapshot.clone(),
        routing_table.clone(),
        http_client.clone(),
        bouncer,
        Some(generic_limiter.clone()),
        &cli,
        &metrics_registry,
        cache.clone(),
    );

    // HTTP server metrics
    let http_metrics = http::server::Metrics::new(&metrics_registry);

    let server_opts = http::server::Options {
        backlog: cli.listen.backlog,
        http1_header_read_timeout: Duration::from_secs(15),
        http2_max_streams: cli.listen.http2_max_streams,
        http2_keepalive_interval: Duration::from_secs(cli.listen.http_keepalive),
        http2_keepalive_timeout: Duration::from_secs(cli.listen.http_keepalive_timeout),
        grace_period: Duration::from_secs(60),
        max_requests_per_conn: Some(1000),
    };

    // HTTP
    let server_http = cli.listen.http_port.map(|x| {
        http::Server::new(
            http::server::Addr::Tcp(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), x)),
            router.clone(),
            server_opts,
            http_metrics.clone(),
            None,
        )
    });

    // HTTP Unix Socket
    let server_http_unix = cli.listen.http_unix_socket.as_ref().map(|x| {
        http::Server::new(
            http::server::Addr::Unix(x.clone()),
            router.clone(),
            server_opts,
            http_metrics.clone(),
            None,
        )
    });

    // HTTPS
    #[cfg(feature = "tls")]
    let server_https = if cli.listen.https_port.is_some() {
        Some(
            setup_https(
                router,
                server_opts.clone(),
                &cli,
                &metrics_registry,
                http_metrics.clone(),
            )
            .context("unable to setup HTTPS")?,
        )
    } else {
        None
    };

    #[cfg(feature = "tls")]
    if server_http.is_none() && server_http_unix.is_none() && server_https.is_none() {
        panic!("at least one of --http-port / --https-port / --http-unix-socket must be specified");
    }

    #[cfg(not(feature = "tls"))]
    if server_http.is_none() && server_http_unix.is_none() {
        panic!("at least one of --http-port / --http-unix-socket must be specified");
    }

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

    let metrics_server = http::Server::new(
        http::server::Addr::Tcp(cli.monitoring.metrics_addr),
        metrics_router,
        server_opts,
        http_metrics,
        None,
    );

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

    let persister = Persister::new(Arc::clone(&routing_table));

    let (registry_replicator, nns_pub_key, mut registry_runners) =
        // Set up registry-related stuff if local store was specified
        if cli.registry.local_store_path.is_some() {
            let RegistrySetupResult(registry_replicator, nns_pub_key, registry_runners) =
                setup_registry(
                    &cli,
                    registry_snapshot.clone(),
                    WithMetricsPersist(persister, MetricParamsPersist::new(&metrics_registry)),
                    http_client.clone(),
                    &metrics_registry,
                )?;

            (registry_replicator, nns_pub_key, registry_runners)
        } else {
            // Otherwise load a stub routing table and snapshot
            let subnet = generate_stub_subnet(cli.registry.stub_replica.clone());
            let snapshot = generate_stub_snapshot(vec![subnet.clone()]);
            let _ = persister.persist(vec![subnet]);
            registry_snapshot.store(Some(Arc::new(snapshot)));

            (None, None, vec![])
        };

    let generic_limiter_runner = WithThrottle(generic_limiter, ThrottleParams::new(10 * SECOND));

    // Runners
    let mut runners: Vec<Box<dyn Run>> =
        vec![Box::new(metrics_runner), Box::new(generic_limiter_runner)];
    runners.append(&mut registry_runners);

    TokioScope::scope_and_block(move |s| {
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

        // HTTP servers
        s.spawn(async move {
            metrics_server
                .serve(CancellationToken::new())
                .map_err(|e| anyhow!("unable to serve metrics: {e:#}"))
                .await
        });

        if let Some(v) = server_http {
            s.spawn(async move {
                v.serve(CancellationToken::new())
                    .map_err(|e| anyhow!("unable to serve http/tcp: {e:#}"))
                    .await
            });
        }

        if let Some(v) = server_http_unix {
            s.spawn(async move {
                v.serve(CancellationToken::new())
                    .map_err(|e| anyhow!("unable to serve http/unix: {e:#}"))
                    .await
            });
        }

        #[cfg(feature = "tls")]
        if let Some(v) = server_https {
            s.spawn(async move {
                v.serve(CancellationToken::new())
                    .map_err(|e| anyhow!("unable to serve https: {e:#}"))
                    .await
            });
        }

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

// Return type for setup_registry() to make clippy happy
struct RegistrySetupResult(
    Option<RegistryReplicator>,
    Option<ThresholdSigPublicKey>,
    Vec<Box<dyn Run>>,
);

// Sets up registry-related stuff
fn setup_registry(
    cli: &Cli,
    registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    persister: WithMetricsPersist<Persister>,
    http_client: Arc<dyn http::Client>,
    metrics_registry: &Registry,
) -> Result<RegistrySetupResult, Error> {
    // Registry Client
    let local_store = Arc::new(LocalStoreImpl::new(
        cli.registry.local_store_path.clone().unwrap(),
    ));

    let registry_client = Arc::new(RegistryClientImpl::new(
        local_store.clone(), // data_provider
        None,                // metrics_registry
    ));

    registry_client
        .fetch_and_start_polling()
        .context("failed to start registry client")?;

    // Snapshots
    let (channel_snapshot_send, channel_snapshot_recv) = tokio::sync::watch::channel(None);
    let snapshot_runner = WithMetricsSnapshot(
        {
            let mut snapshotter = Snapshotter::new(
                Arc::clone(&registry_snapshot),
                channel_snapshot_send,
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
        MetricParamsSnapshot::new(metrics_registry),
    );

    let snapshot_runner = WithThrottle(snapshot_runner, ThrottleParams::new(5 * SECOND));

    // Checks
    let checker = Checker::new(http_client, Duration::from_millis(cli.health.check_timeout));
    let checker = WithMetricsCheck(checker, MetricParamsCheck::new(metrics_registry));

    let check_runner = CheckRunner::new(
        channel_snapshot_recv,
        cli.health.max_height_lag,
        Arc::new(persister),
        Arc::new(checker),
        Duration::from_millis(cli.health.check_interval),
        Duration::from_millis(cli.health.update_interval),
    );

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
                    .clone()
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

    Ok(RegistrySetupResult(
        registry_replicator,
        nns_pub_key,
        vec![Box::new(snapshot_runner), Box::new(check_runner)],
    ))
}

#[cfg(feature = "tls")]
fn setup_tls_resolver(cli: &cli::TlsConfig) -> Result<Arc<dyn ResolvesServerCert>, Error> {
    use ic_bn_lib::tls;
    use tokio_util::sync::CancellationToken;

    let resolver = if let Some(v) = &cli.acme_credentials_path {
        warn!("TLS: Using ACME ALPN-01 (staging: {})", cli.acme_staging);

        let hostname = cli
            .hostname
            .clone()
            .ok_or(anyhow!("hostname not specified"))?;

        let opts = tls::acme::AcmeOptions::new(
            vec![hostname],
            v.clone(),
            Duration::from_secs(86400 * 14),
            false,
            cli.acme_staging,
            "mailto:boundary-nodes@dfinity.org".into(),
        );

        tls::acme::alpn::new(opts, CancellationToken::new())
    } else {
        warn!("TLS: Using static certificates");

        let cert = cli
            .tls_cert_path
            .clone()
            .ok_or(anyhow!("TLS cert not specified"))?;
        let key = cli
            .tls_pkey_path
            .clone()
            .ok_or(anyhow!("TLS key not specified"))?;

        let cert = std::fs::read(cert).context("unable to read TLS cert")?;
        let key = std::fs::read(key).context("unable to read TLS key")?;

        let resolver = tls::StubResolver::new(&cert, &key)?;
        Arc::new(resolver)
    };

    Ok(resolver)
}

#[cfg(feature = "tls")]
fn setup_https(
    router: Router,
    opts: http::server::Options,
    cli: &Cli,
    registry: &Registry,
    metrics: http::server::Metrics,
) -> Result<http::Server, Error> {
    use ic_bn_lib::tls;

    let resolver = setup_tls_resolver(&cli.tls).context("unable to setup TLS resolver")?;

    // TODO add CLI
    let session_storage = Arc::new(tls::sessions::Storage::new(
        256 * 1024 * 1024,
        Duration::from_secs(18 * 3600),
    ));

    let rustls_config = tls::prepare_server_config(
        resolver,
        session_storage,
        &vec![http::ALPN_ACME.to_vec()],
        // TODO add CLI
        Duration::from_secs(9 * 3600),
        &[&rustls::version::TLS13],
        &registry,
    );

    let server_https = http::Server::new(
        http::server::Addr::Tcp(SocketAddr::new(
            Ipv6Addr::UNSPECIFIED.into(),
            cli.listen.https_port.unwrap(),
        )),
        router,
        opts,
        metrics,
        Some(rustls_config),
    );

    Ok(server_https)
}

pub fn setup_router(
    registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    routing_table: Arc<ArcSwapOption<Routes>>,
    http_client: Arc<dyn http::Client>,
    bouncer: Option<Arc<bouncer::Bouncer>>,
    generic_limiter: Option<Arc<generic::Limiter>>,
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
            post(routes::handle_canister).with_state(proxy.clone())
        })
        .layer(option_layer(cache.map(|x| {
            middleware::from_fn_with_state(x.clone(), cache_middleware)
        })));

    let call_route = {
        let mut route = Router::new()
            .route(routes::PATH_CALL, {
                post(routes::handle_canister).with_state(proxy.clone())
            })
            .route(routes::PATH_CALL_V3, {
                post(routes::handle_canister).with_state(proxy.clone())
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

    let middleware_geoip = option_layer(cli.monitoring.geoip_db.as_ref().map(|x| {
        middleware::from_fn_with_state(
            Arc::new(geoip::GeoIp::new(x).expect("unable to load GeoIP")),
            geoip::middleware,
        )
    }));

    let middleware_metrics = option_layer((!cli.monitoring.disable_request_logging).then_some(
        middleware::from_fn_with_state(
            HttpMetricParams::new(
                metrics_registry,
                "http_request",
                cli.monitoring.log_failed_requests_only,
            ),
            metrics::metrics_middleware,
        ),
    ));

    let middleware_concurrency =
        option_layer(cli.listen.max_concurrency.map(ConcurrencyLimitLayer::new));

    let middleware_retry = middleware::from_fn_with_state(
        RetryParams {
            retry_count: cli.retry.retry_count as usize,
            retry_update_call: cli.retry.retry_update_call,
            disable_latency_routing: cli.retry.disable_latency_routing,
        },
        retry_request,
    );

    let middleware_shedding = option_layer(cli.listen.shed_ewma_param.map(|x| {
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
    }));

    let middlware_bouncer =
        option_layer(bouncer.map(|x| middleware::from_fn_with_state(x, bouncer::middleware)));
    let middleware_subnet_lookup = middleware::from_fn_with_state(lookup, routes::lookup_subnet);
    let middleware_generic_limiter = option_layer(
        generic_limiter.map(|x| middleware::from_fn_with_state(x, generic::middleware)),
    );

    // Layers under ServiceBuilder are executed top-down (opposite to that under Router)
    // 1st layer wraps 2nd layer and so on
    let common_service_layers = ServiceBuilder::new()
        .layer(middlware_bouncer)
        .layer(middleware_geoip)
        .set_x_request_id(MakeRequestUuid)
        .layer(middleware_metrics)
        .layer(middleware_concurrency)
        .layer(middleware_shedding)
        .layer(middleware::from_fn(routes::postprocess_response))
        .layer(middleware::from_fn(routes::preprocess_request));

    let service_canister_read_call_query = ServiceBuilder::new()
        .layer(middleware::from_fn(routes::validate_request))
        .layer(middleware::from_fn(routes::validate_canister_request))
        .layer(common_service_layers.clone())
        .layer(middleware_subnet_lookup.clone())
        .layer(middleware_generic_limiter.clone())
        .layer(middleware_retry.clone());

    let service_subnet_read = ServiceBuilder::new()
        .layer(middleware::from_fn(routes::validate_request))
        .layer(middleware::from_fn(routes::validate_subnet_request))
        .layer(common_service_layers)
        .layer(middleware_subnet_lookup)
        .layer(middleware_generic_limiter)
        .layer(middleware_retry);

    let canister_read_state_route = Router::new().route(routes::PATH_READ_STATE, {
        post(routes::handle_canister).with_state(proxy.clone())
    });

    let canister_read_call_query_routes = query_route
        .merge(call_route)
        .merge(canister_read_state_route)
        .layer(service_canister_read_call_query);

    let subnet_read_state_route = Router::new()
        .route(routes::PATH_SUBNET_READ_STATE, {
            post(routes::handle_subnet).with_state(proxy.clone())
        })
        .layer(service_subnet_read);

    canister_read_call_query_routes
        .merge(subnet_read_state_route)
        .merge(status_route)
        .merge(health_route)
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

        if out.is_err() {
            error!(action, status, duration, error = ?out.as_ref().err());
        } else {
            debug!(action, status, duration, error = ?out.as_ref().err());
        }

        out
    }
}

#[allow(dead_code)]
pub struct WithRetry<T>(
    pub T,
    pub Duration, // attempt_interval
);

pub struct ThrottleParams {
    pub throttle_duration: Duration,
    pub next_time: Option<Instant>,
}

impl ThrottleParams {
    pub fn new(throttle_duration: Duration) -> Self {
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
