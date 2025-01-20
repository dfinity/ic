#![allow(clippy::disallowed_types)]
use std::{
    error::Error as StdError,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use anonymization_client::{
    Canister as AnonymizationCanister,
    CanisterMethodsBuilder as AnonymizationCanisterMethodsBuilder, Track,
    Tracker as AnonymizationTracker,
};
use anyhow::{anyhow, Context, Error};
use arc_swap::ArcSwapOption;
use async_scoped::TokioScope;
use async_trait::async_trait;
use axum::extract::Request;
use axum::{
    middleware,
    response::IntoResponse,
    routing::method_routing::{get, post},
    Router,
};
use axum_extra::middleware::option_layer;
use candid::DecoderConfig;
use futures::TryFutureExt;
use ic_bn_lib::{
    http::{
        self,
        shed::{
            sharded::{ShardedLittleLoadShedderLayer, ShardedOptions, TypeExtractor},
            system::{SystemInfo, SystemLoadShedderLayer},
            ShedResponse,
        },
    },
    types::RequestType,
};
use ic_canister_client::{Agent, Sender};
use ic_config::crypto::CryptoConfig;
use ic_crypto::CryptoComponent;
use ic_crypto_utils_basic_sig::conversions::derive_node_id;
use ic_interfaces::crypto::{BasicSigner, KeyManager};
use ic_interfaces_registry::ZERO_REGISTRY_VERSION;
use ic_logger::replica_logger::no_op_logger;
use ic_registry_client::client::{RegistryClient, RegistryClientImpl};
use ic_registry_local_store::{LocalStore, LocalStoreImpl};
use ic_registry_replicator::RegistryReplicator;
use ic_types::{crypto::threshold_sig::ThresholdSigPublicKey, messages::MessageId};
use nix::unistd::{getpgid, setpgid, Pid};
use prometheus::Registry;
use rand::rngs::OsRng;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tower::{limit::ConcurrencyLimitLayer, util::MapResponseLayer, ServiceBuilder};
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
    if cli.http_client.http_client_timeout_connect > cli.health.health_check_timeout {
        panic!("Health check timeout should be longer than HTTP client connect timeout");
    }

    if !(cli.registry.registry_local_store_path.is_none()
        ^ cli.registry.registry_stub_replica.is_empty())
    {
        panic!("Local store path and Stub Replica are mutually exclusive and at least one of them must be specified");
    }

    // Make sure ic-boundary is the leader of its own process group
    // Needed for correct execution of API BNs
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
        metrics_addr = cli.obs.obs_metrics_addr.to_string().as_str(),
    );

    let mut runners: Vec<Box<dyn Run>> = vec![];
    let routing_table = Arc::new(ArcSwapOption::empty());
    let registry_snapshot = Arc::new(ArcSwapOption::empty());

    // DNS
    let dns_resolver = DnsResolver::new(Arc::clone(&registry_snapshot));

    // TLS client
    let tls_verifier = Arc::new(TlsVerifier::new(
        Arc::clone(&registry_snapshot),
        cli.misc.skip_replica_tls_verification,
    ));

    let mut tls_config_client =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous() // Nothing really dangerous here
            .with_custom_certificate_verifier(tls_verifier)
            .with_no_client_auth();

    // Enable ALPN to negotiate HTTP version
    let mut alpn = vec![];
    if !cli.network.network_disable_http2_client {
        alpn.push(b"h2".to_vec());
    }
    alpn.push(b"http/1.1".to_vec());
    tls_config_client.alpn_protocols = alpn;

    // Set larger session resumption cache to accomodate all replicas (256 by default)
    tls_config_client.resumption = rustls::client::Resumption::in_memory_sessions(
        4096 * cli.network.network_http_client_count as usize,
    );

    let mut http_client_opts: http::client::Options<DnsResolver> = (&cli.http_client).into();
    http_client_opts.user_agent = SERVICE_NAME.into();
    http_client_opts.tls_config = Some(tls_config_client);
    http_client_opts.dns_resolver = Some(dns_resolver);

    // HTTP client for health checks
    let http_client_check = http::client::ReqwestClient::new(http_client_opts.clone())
        .context("unable to create HTTP client for checks")?;
    let http_client_check = Arc::new(http_client_check);

    // HTTP client for normal requests
    let http_client = http::client::ReqwestClientLeastLoaded::new(
        http_client_opts,
        cli.network.network_http_client_count as usize,
    )
    .context("unable to create HTTP client")?;
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

    // Setup registry-related stuff
    let persister = Persister::new(Arc::clone(&routing_table));

    // Snapshot update notification channels
    let (channel_snapshot_send, channel_snapshot_recv) = tokio::sync::watch::channel(None);

    // Registry Client
    let (registry_client, registry_replicator, nns_pub_key) =
        if let Some(v) = &cli.registry.registry_local_store_path {
            // Store
            let local_store = Arc::new(LocalStoreImpl::new(v.clone()));

            // Client
            let registry_client = Arc::new(RegistryClientImpl::new(local_store.clone(), None));
            registry_client
                .fetch_and_start_polling()
                .context("failed to start registry client")?;

            // Snapshotting
            let (registry_replicator, nns_pub_key) = setup_registry(
                &cli,
                local_store.clone(),
                registry_client.clone(),
                registry_snapshot.clone(),
                WithMetricsPersist(persister, MetricParamsPersist::new(&metrics_registry)),
                http_client_check,
                &metrics_registry,
                channel_snapshot_send,
                channel_snapshot_recv.clone(),
                &mut runners,
            )?;

            (Some(registry_client), registry_replicator, nns_pub_key)
        } else {
            // Prepare a stub routing table and snapshot if there's no local store specified
            let subnet = generate_stub_subnet(cli.registry.registry_stub_replica.clone());
            let snapshot = generate_stub_snapshot(vec![subnet.clone()]);
            let _ = persister.persist(vec![subnet]);
            registry_snapshot.store(Some(Arc::new(snapshot)));

            (None, None, None)
        };

    // IC Agent
    let agent = if cli.rate_limiting.rate_limit_generic_canister_id.is_some()
        || cli.obs.obs_log_anonymization_canister_id.is_some()
    {
        if cli.misc.crypto_config.is_some() && registry_client.is_none() {
            return Err(anyhow!(
                "IC-Agent: registry client is required when crypto-config is in use"
            ));
        }

        if cli.misc.crypto_config.is_none() {
            warn!("IC-Agent: crypto-config is missing, using anonymous principal");
        }

        let agent = create_agent(
            cli.misc.crypto_config.clone(),
            registry_client,
            cli.listen.listen_http_port_loopback,
        )
        .await?;

        Some(agent)
    } else {
        None
    };

    // Caching
    let cache = cli.cache.cache_size.map(|x| {
        Arc::new(
            Cache::new(
                x,
                cli.cache.cache_max_item_size,
                cli.cache.cache_ttl,
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
    let generic_limiter_opts = generic::Options {
        tti: cli.rate_limiting.rate_limit_generic_tti,
        max_shards: cli.rate_limiting.rate_limit_generic_max_shards,
        poll_interval: cli.rate_limiting.rate_limit_generic_poll_interval,
        autoscale: cli.rate_limiting.rate_limit_generic_autoscale,
    };
    let generic_limiter = if let Some(v) = &cli.rate_limiting.rate_limit_generic_file {
        Some(Arc::new(generic::GenericLimiter::new_from_file(
            v.clone(),
            generic_limiter_opts,
            channel_snapshot_recv,
            &metrics_registry,
        )))
    } else if let Some(v) = cli.rate_limiting.rate_limit_generic_canister_id {
        Some(Arc::new(generic::GenericLimiter::new_from_canister(
            v,
            agent.clone().unwrap(),
            generic_limiter_opts,
            cli.misc.crypto_config.is_some(),
            channel_snapshot_recv,
            &metrics_registry,
        )))
    } else {
        None
    };

    // HTTP Logs Anonymization
    let anonymization_salt = Arc::new(ArcSwapOption::<Vec<u8>>::empty());

    // Prepare Axum Router
    let router = setup_router(
        registry_snapshot.clone(),
        routing_table.clone(),
        http_client,
        bouncer,
        generic_limiter.clone(),
        &cli,
        &metrics_registry,
        cache.clone(),
        anonymization_salt.clone(),
    );

    // HTTP server metrics
    let http_metrics = http::server::Metrics::new(&metrics_registry);

    // HTTP server options
    let server_opts: http::server::Options = (&cli.http_server).into();

    // HTTP
    let server_http = cli.listen.listen_http_port.map(|x| {
        http::Server::new(
            http::server::Addr::Tcp(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), x)),
            router.clone(),
            server_opts,
            http_metrics.clone(),
            None,
        )
    });

    // HTTP Unix Socket
    let server_http_unix = cli.listen.listen_http_unix_socket.as_ref().map(|x| {
        http::Server::new(
            http::server::Addr::Unix(x.clone()),
            router.clone(),
            server_opts,
            http_metrics.clone(),
            None,
        )
    });

    // HTTP loopback server.
    // Allows internal agents to work and be independent of the normal listening ports.
    // Probably we can find some way of working w/o a dedicated port (e.g. over memory) but it would be hard
    // to adapt HTTP clients for it.
    let server_http_loopback = agent.is_some().then(|| {
        http::Server::new(
            http::server::Addr::Tcp(SocketAddr::new(
                Ipv4Addr::LOCALHOST.into(),
                cli.listen.listen_http_port_loopback,
            )),
            router.clone(),
            server_opts,
            http_metrics.clone(),
            None,
        )
    });

    // HTTPS
    #[cfg(feature = "tls")]
    let server_https = if cli.listen.listen_https_port.is_some() {
        Some(
            setup_https(
                router,
                server_opts,
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
        http::server::Addr::Tcp(cli.obs.obs_metrics_addr),
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

    // Runners
    runners.push(Box::new(metrics_runner));

    if let Some(v) = generic_limiter {
        runners.push(Box::new(v));
    }

    // HTTP Logs Anonymization
    let tracker = if let Some(v) = cli.obs.obs_log_anonymization_canister_id {
        let canister = AnonymizationCanister::new(agent.clone().unwrap(), v);
        let cm = AnonymizationCanisterMethodsBuilder::new(canister)
            .with_metrics(&metrics_registry)
            .build();
        Some(AnonymizationTracker::new(Box::new(OsRng), cm)?)
    } else {
        None
    };

    TokioScope::scope_and_block(move |s| {
        if let Some(v) = registry_replicator {
            s.spawn(async move {
                v.start_polling(cli.registry.registry_nns_urls, nns_pub_key)
                    .await
                    .context("failed to start registry replicator")?
                    .await
                    .context("registry replicator failed")?;

                Ok::<(), Error>(())
            });
        }

        // Anonymization Tracker
        if let Some(mut t) = tracker {
            s.spawn(async move {
                t.track(|value| {
                    anonymization_salt.store(Some(Arc::new(value)));
                })
                .await
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

        if let Some(v) = server_http_loopback {
            s.spawn(async move {
                v.serve(CancellationToken::new())
                    .map_err(|e| anyhow!("unable to serve http/tcp/loopback: {e:#}"))
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

async fn create_sender(
    crypto_config: CryptoConfig,
    registry_client: Arc<RegistryClientImpl>,
) -> Result<Sender, Error> {
    let crypto_component = tokio::task::spawn_blocking({
        let registry_client = Arc::clone(&registry_client);

        move || {
            Arc::new(CryptoComponent::new(
                &crypto_config,
                Some(tokio::runtime::Handle::current()),
                registry_client,
                no_op_logger(),
                None,
            ))
        }
    })
    .await?;

    let public_key = tokio::task::spawn_blocking({
        let crypto_component = Arc::clone(&crypto_component);

        move || {
            crypto_component
                .current_node_public_keys()
                .map_err(|e| anyhow!("failed to retrieve public key: {e:#}"))?
                .node_signing_public_key
                .context("missing node public key")
        }
    })
    .await??;

    let node_id = derive_node_id(&public_key).expect("failed to derive node id");

    // Custom Signer
    Ok(Sender::Node {
        pub_key: public_key.key_value,
        sign: Arc::new(move |msg: &MessageId| {
            #[allow(clippy::disallowed_methods)]
            let sig = tokio::task::block_in_place(|| {
                crypto_component
                    .sign_basic(msg, node_id, registry_client.get_latest_version())
                    .map(|value| value.get().0)
                    .map_err(|err| anyhow!("failed to sign message: {err:?}"))
            })?;

            Ok(sig)
        }),
    })
}

async fn create_agent(
    crypto_config: Option<CryptoConfig>,
    registry_client: Option<Arc<RegistryClientImpl>>,
    port: u16,
) -> Result<Agent, Error> {
    let sender = if let (Some(v), Some(r)) = (crypto_config, registry_client) {
        create_sender(v, r).await?
    } else {
        Sender::Anonymous
    };

    let agent = Agent::new(format!("http://127.0.0.1:{port}").parse()?, sender);
    Ok(agent)
}

// Sets up registry-related stuff
fn setup_registry(
    cli: &Cli,
    local_store: Arc<dyn LocalStore>,
    registry_client: Arc<dyn RegistryClient>,
    registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    persister: WithMetricsPersist<Persister>,
    http_client_check: Arc<dyn http::Client>,
    metrics_registry: &Registry,
    channel_snapshot_send: watch::Sender<Option<Arc<RegistrySnapshot>>>,
    channel_snapshot_recv: watch::Receiver<Option<Arc<RegistrySnapshot>>>,
    runners: &mut Vec<Box<dyn Run>>,
) -> Result<(Option<RegistryReplicator>, Option<ThresholdSigPublicKey>), Error> {
    // Snapshots
    let snapshot_runner = WithMetricsSnapshot(
        {
            let mut snapshotter = Snapshotter::new(
                Arc::clone(&registry_snapshot),
                channel_snapshot_send,
                registry_client.clone(),
                cli.registry.registry_min_version_age,
            );

            if let Some(v) = &cli.nftables.nftables_system_replicas_path {
                let fw_reloader = SystemdReloader::new(SYSTEMCTL_BIN.into(), "nftables", "reload");

                let fw_generator = FirewallGenerator::new(
                    v.clone(),
                    cli.nftables.nftables_system_replicas_var.clone(),
                );

                let persister = SnapshotPersister::new(fw_generator, fw_reloader);
                snapshotter.set_persister(persister);
            }

            snapshotter
        },
        MetricParamsSnapshot::new(metrics_registry),
    );

    let snapshot_runner = WithThrottle(snapshot_runner, ThrottleParams::new(5 * SECOND));
    runners.push(Box::new(snapshot_runner));

    // Checks
    let checker = Checker::new(http_client_check, cli.health.health_check_timeout);
    let checker = WithMetricsCheck(checker, MetricParamsCheck::new(metrics_registry));

    let check_runner = CheckRunner::new(
        channel_snapshot_recv,
        cli.health.health_max_height_lag,
        Arc::new(persister),
        Arc::new(checker),
        cli.health.health_check_interval,
        cli.health.health_update_interval,
    );
    runners.push(Box::new(check_runner));

    let (registry_replicator, nns_pub_key) = if !cli.registry.registry_disable_replicator {
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
                    .registry_nns_pub_key_pem
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
                cli.registry.registry_nns_poll_interval,
            )),
            nns_pub_key,
        )
    } else {
        (None, None)
    };

    Ok((registry_replicator, nns_pub_key))
}

#[cfg(feature = "tls")]
fn setup_tls_resolver_stub(cli: &cli::Tls) -> Result<Arc<dyn ResolvesServerCert>, Error> {
    use ic_bn_lib::tls;

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
    Ok(Arc::new(resolver))
}

#[cfg(feature = "tls")]
fn setup_tls_resolver_acme(cli: &cli::Tls) -> Result<Arc<dyn ResolvesServerCert>, Error> {
    use ic_bn_lib::tls;
    use tokio_util::sync::CancellationToken;

    let path = cli
        .tls_acme_credentials_path
        .clone()
        .ok_or(anyhow!("ACME credentials path not specified"))?;

    let hostname = cli
        .tls_hostname
        .clone()
        .ok_or(anyhow!("hostname not specified"))?;

    let opts = tls::acme::AcmeOptions::new(
        vec![hostname],
        path,
        // Does not matter, rustls-acme renews after 45 days always
        Duration::from_secs(1),
        false,
        cli.tls_acme_staging,
        "mailto:boundary-nodes@dfinity.org".into(),
    );

    Ok(tls::acme::alpn::new(opts, CancellationToken::new()))
}

/// Try to load the static resolver first, then ACME one.
/// This is needed for integration tests where we cannot easily separate test/prod environments
#[cfg(feature = "tls")]
fn setup_tls_resolver(cli: &cli::Tls) -> Result<Arc<dyn ResolvesServerCert>, Error> {
    warn!("TLS: Trying resolver: static files");
    match setup_tls_resolver_stub(cli) {
        Ok(v) => {
            warn!("TLS: static resolver loaded");
            return Ok(v);
        }

        Err(e) => warn!("TLS: unable to load static resolver: {e}"),
    }

    warn!(
        "TLS: Trying resolver: ACME ALPN-01 (staging: {})",
        cli.tls_acme_staging
    );
    match setup_tls_resolver_acme(cli) {
        Ok(v) => {
            warn!("TLS: ACME resolver loaded");
            return Ok(v);
        }

        Err(e) => warn!("TLS: unable to load ACME resolver: {e}"),
    }

    Err(anyhow!("TLS: no resolvers were able to load"))
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

    let tls_opts = tls::Options {
        additional_alpn: vec![http::ALPN_ACME.to_vec()],
        sessions_count: cli.http_server.http_server_tls_session_cache_size,
        sessions_tti: cli.http_server.http_server_tls_session_cache_tti,
        ticket_lifetime: cli.http_server.http_server_tls_ticket_lifetime,
        tls_versions: vec![&rustls::version::TLS13],
    };

    let rustls_config = tls::prepare_server_config(tls_opts, resolver, registry);

    let server_https = http::Server::new(
        http::server::Addr::Tcp(SocketAddr::new(
            Ipv6Addr::UNSPECIFIED.into(),
            cli.listen.listen_https_port.unwrap(),
        )),
        router,
        opts,
        metrics,
        Some(rustls_config),
    );

    Ok(server_https)
}

#[derive(Clone, Debug)]
struct RequestTypeExtractor;
impl TypeExtractor for RequestTypeExtractor {
    type Type = RequestType;
    type Request = Request;

    fn extract(&self, req: &Self::Request) -> Option<Self::Type> {
        req.extensions().get::<RequestType>().copied()
    }
}

pub fn setup_router(
    registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    routing_table: Arc<ArcSwapOption<Routes>>,
    http_client: Arc<dyn http::Client>,
    bouncer: Option<Arc<bouncer::Bouncer>>,
    generic_limiter: Option<Arc<generic::GenericLimiter>>,
    cli: &Cli,
    metrics_registry: &Registry,
    cache: Option<Arc<Cache>>,
    anonymization_salt: Arc<ArcSwapOption<Vec<u8>>>,
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

    let middleware_geoip = option_layer(cli.misc.geoip_db.as_ref().map(|x| {
        middleware::from_fn_with_state(
            Arc::new(geoip::GeoIp::new(x).expect("unable to load GeoIP")),
            geoip::middleware,
        )
    }));

    let middleware_metrics = option_layer((!cli.obs.obs_disable_request_logging).then_some(
        middleware::from_fn_with_state(
            HttpMetricParams::new(
                metrics_registry,
                "http_request",
                cli.obs.obs_log_failed_requests_only,
                anonymization_salt,
            ),
            metrics::metrics_middleware,
        ),
    ));

    let middleware_concurrency = option_layer(
        cli.load
            .load_max_concurrency
            .map(ConcurrencyLimitLayer::new),
    );

    let middleware_retry = middleware::from_fn_with_state(
        RetryParams {
            retry_count: cli.retry.retry_count as usize,
            retry_update_call: cli.retry.retry_update_call,
            disable_latency_routing: cli.retry.retry_disable_latency_routing,
        },
        retry_request,
    );

    // Load shedders

    // We need to map the generic response of a shedder to an Axum's Response
    let shed_map_response = MapResponseLayer::new(|resp| match resp {
        ShedResponse::Inner(inner) => inner,
        ShedResponse::Overload(_) => ErrorCause::LoadShed.into_response(),
    });

    let load_shedder_system_mw = option_layer({
        let opts = &[
            cli.shed_system.shed_system_cpu,
            cli.shed_system.shed_system_memory,
            cli.shed_system.shed_system_load_avg_1,
            cli.shed_system.shed_system_load_avg_5,
            cli.shed_system.shed_system_load_avg_15,
        ];

        if opts.iter().any(|x| x.is_some()) {
            warn!("System load shedder enabled ({:?})", cli.shed_system);

            Some(
                ServiceBuilder::new()
                    .layer(shed_map_response.clone())
                    .layer(SystemLoadShedderLayer::new(
                        cli.shed_system.shed_system_ewma,
                        cli.shed_system.clone().into(),
                        SystemInfo::new(),
                    )),
            )
        } else {
            None
        }
    });

    let load_shedder_latency_mw =
        option_layer(if !cli.shed_latency.shed_sharded_latency.is_empty() {
            warn!("Latency load shedder enabled ({:?})", cli.shed_latency);

            Some(ServiceBuilder::new().layer(shed_map_response).layer(
                ShardedLittleLoadShedderLayer::new(ShardedOptions {
                    extractor: RequestTypeExtractor,
                    ewma_alpha: cli.shed_latency.shed_sharded_ewma,
                    passthrough_count: cli.shed_latency.shed_sharded_passthrough,
                    latencies: cli.shed_latency.shed_sharded_latency.clone(),
                }),
            ))
        } else {
            None
        });

    let middleware_bouncer =
        option_layer(bouncer.map(|x| middleware::from_fn_with_state(x, bouncer::middleware)));
    let middleware_subnet_lookup = middleware::from_fn_with_state(lookup, routes::lookup_subnet);
    let middleware_generic_limiter = option_layer(
        generic_limiter.map(|x| middleware::from_fn_with_state(x, generic::middleware)),
    );

    // Layers under ServiceBuilder are executed top-down (opposite to that under Router)
    // 1st layer wraps 2nd layer and so on
    let common_service_layers = ServiceBuilder::new()
        .layer(middleware_bouncer)
        .layer(middleware_geoip)
        .set_x_request_id(MakeRequestUuid)
        .layer(middleware_metrics)
        .layer(load_shedder_system_mw)
        .layer(middleware_concurrency)
        .layer(middleware::from_fn(routes::postprocess_response))
        .layer(middleware::from_fn(routes::preprocess_request))
        .layer(load_shedder_latency_mw);

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
