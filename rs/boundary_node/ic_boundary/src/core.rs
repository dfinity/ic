#![allow(clippy::disallowed_types)]
use std::{
    error::Error as StdError,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::{Context, Error, anyhow, bail};
use arc_swap::ArcSwapOption;
use axum::{
    Router,
    extract::Request,
    middleware,
    response::IntoResponse,
    routing::method_routing::{any, get, post},
};
use axum_extra::middleware::option_layer;
use candid::{DecoderConfig, Principal};
use ic_agent::{Agent, Identity, Signature, agent::EnvelopeContent, identity::AnonymousIdentity};
use ic_bn_lib::{
    http::{
        self as bnhttp,
        shed::{
            sharded::ShardedLittleLoadShedderLayer,
            system::{SystemInfo, SystemLoadShedderLayer},
        },
    },
    prometheus::Registry,
    pubsub::BrokerBuilder,
    tasks::TaskManager,
    tls::{acme::alpn as AcmeAlpn, resolver::StubResolver, verify::NoopServerCertVerifier},
};
use ic_bn_lib_common::{
    traits::{http::Client, shed::TypeExtractor},
    types::{
        http::{ALPN_ACME, ClientOptions, Metrics as HttpServerMetrics, ServerOptions},
        shed::{ShardedOptions, ShedResponse},
        tls::TlsOptions,
    },
};
use ic_config::crypto::CryptoConfig;
use ic_crypto::CryptoComponent;
use ic_crypto_utils_threshold_sig_der::{
    parse_threshold_sig_key_from_pem_file, threshold_sig_public_key_to_der,
};
use ic_interfaces::crypto::{BasicSigner, KeyManager};
use ic_interfaces_registry::RegistryClient;
use ic_logger::replica_logger::no_op_logger;
use ic_protobuf::registry::crypto::v1::{AlgorithmId, PublicKey};
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::{crypto::CryptoRegistry, subnet::SubnetRegistry};
use ic_registry_local_store::LocalStoreImpl;
use ic_types::messages::MessageId;
use nix::unistd::{Pid, getpgid, setpgid};
use rustls::{client::danger::ServerCertVerifier, server::ResolvesServerCert};
use tokio::{
    select,
    signal::unix::SignalKind,
    sync::{Mutex, watch},
};
use tower::{ServiceBuilder, limit::ConcurrencyLimitLayer, util::MapResponseLayer};
use tower_http::{ServiceBuilderExt, compression::CompressionLayer, request_id::MakeRequestUuid};
use tracing::warn;

use crate::{
    bouncer,
    check::{Checker, Runner as CheckRunner},
    cli::{self, Cli},
    dns::DnsResolver,
    errors::ErrorCause,
    http::{
        PATH_CALL_V2, PATH_CALL_V3, PATH_CALL_V4, PATH_HEALTH, PATH_QUERY_V2, PATH_QUERY_V3,
        PATH_READ_STATE_V2, PATH_READ_STATE_V3, PATH_STATUS, PATH_SUBNET_READ_STATE_V2,
        PATH_SUBNET_READ_STATE_V3, RequestType,
        handlers::{self, LogsState, logs_canister},
        middleware::{
            cache::{CacheState, cache_middleware},
            cors::{self},
            geoip::{self},
            process::{self},
            retry::{RetryParams, retry_request},
            validate::{self, UUID_REGEX},
        },
    },
    metrics::{
        self, HttpMetricParams, HttpMetricParamsStatus, MetricParamsCheck, MetricParamsPersist,
        MetricParamsSnapshot, MetricsCache, MetricsRunner, WithMetricsCheck, WithMetricsPersist,
        WithMetricsSnapshot,
    },
    persist::{Persist, Persister},
    rate_limiting::{RateLimit, generic},
    routes::{self, Health, Lookup, Proxy, ProxyRouter, RootKey},
    salt_fetcher::AnonymizationSaltFetcher,
    snapshot::{RegistrySnapshot, Snapshotter, generate_stub_snapshot, generate_stub_subnet},
    tls_verify::TlsVerifier,
};

pub const SERVICE_NAME: &str = "ic_boundary";
pub const AUTHOR_NAME: &str = "Boundary Node Team <boundary-nodes@dfinity.org>";

pub const SECOND: Duration = Duration::from_secs(1);

const KB: usize = 1024;
const MB: usize = 1024 * KB;

pub const MAX_REQUEST_BODY_SIZE: usize = 4 * MB;
const METRICS_CACHE_CAPACITY: usize = 15 * MB;

pub const ANONYMOUS_PRINCIPAL: Principal = Principal::anonymous();

pub fn decoder_config() -> DecoderConfig {
    let mut config = DecoderConfig::new();
    // Limit the amount of work for skipping unneeded data on the wire when parsing Candid.
    // The value of 10_000 follows the Candid recommendation.
    config.set_skipping_quota(10_000);
    config.set_full_error_message(false);
    config
}

pub async fn main(mut cli: Cli) -> Result<(), Error> {
    if cli.http_client.http_client_timeout_connect > cli.health.health_check_timeout {
        cli.health.health_check_timeout = cli.http_client.http_client_timeout_connect;

        warn!(
            "`--health-check-timeout` should be longer than `--http-client-timeout-connect`, increasing it to client timeout"
        );
    }

    warn!("Starting {SERVICE_NAME}");

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

    let mut tasks = TaskManager::new();

    let routing_table = Arc::new(ArcSwapOption::empty());
    let registry_snapshot = Arc::new(ArcSwapOption::empty());

    // Setup Registry-based DNS resolver
    let dns_resolver = DnsResolver::new(registry_snapshot.clone());

    // TLS client

    // Pick a TLS certificate verifier - Registry-based or a No-op one
    let tls_verifier: Arc<dyn ServerCertVerifier> = if cli.misc.skip_replica_tls_verification {
        Arc::new(NoopServerCertVerifier::default())
    } else {
        Arc::new(TlsVerifier::new(registry_snapshot.clone()))
    };

    // We talk only TLS1.3 to the replicas
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

    // HTTP clients

    let mut http_client_opts: ClientOptions = (&cli.http_client).into();
    http_client_opts.user_agent = SERVICE_NAME.into();
    http_client_opts.tls_config = Some(tls_config_client);

    // HTTP client for health checks
    let http_client_check =
        bnhttp::ReqwestClient::new(http_client_opts.clone(), Some(dns_resolver.clone()))
            .context("unable to create HTTP client for checks")?;
    let http_client_check = Arc::new(http_client_check);

    // HTTP client for normal requests.
    // Pick normal or LeastLoaded one depending on if we need >1 client
    let http_client = if cli.network.network_http_client_count > 1 {
        Arc::new(
            bnhttp::ReqwestClientLeastLoaded::new(
                http_client_opts,
                Some(dns_resolver.clone()),
                cli.network.network_http_client_count as usize,
                Some(&metrics_registry),
            )
            .context("unable to create HTTP client")?,
        ) as Arc<dyn Client>
    } else {
        Arc::new(
            bnhttp::ReqwestClient::new(http_client_opts, Some(dns_resolver.clone()))
                .context("unable to create HTTP client")?,
        ) as Arc<dyn Client>
    };

    // Setup registry-related stuff
    let persister = Persister::new(routing_table.clone());

    // Snapshot update notification channels
    let (channel_snapshot_send, channel_snapshot_recv) = tokio::sync::watch::channel(None);

    // Registry Client
    let registry_client = if cli.registry.registry_local_store_path.is_some() {
        let persister = WithMetricsPersist(persister, MetricParamsPersist::new(&metrics_registry));

        // Snapshotting
        Some(
            setup_registry(
                &cli,
                registry_snapshot.clone(),
                persister,
                http_client_check,
                &metrics_registry,
                channel_snapshot_send,
                channel_snapshot_recv.clone(),
                &mut tasks,
            )
            .await
            .context("unable to init Registry")?,
        )
    } else {
        // Prepare a stub routing table and snapshot if there's no local store specified
        let subnet = generate_stub_subnet(cli.registry.registry_stub_replica.clone());
        let snapshot = generate_stub_snapshot(vec![subnet.clone()]);
        let _ = persister.persist(vec![subnet]);
        registry_snapshot.store(Some(Arc::new(snapshot)));

        None
    };

    // IC Agent
    let agent = if cli.rate_limiting.rate_limit_generic_canister_id.is_some()
        || cli.obs.obs_log_anonymization_canister_id.is_some()
    {
        if cli.misc.crypto_config.is_some() && registry_client.is_none() {
            bail!("IC-Agent: registry client is required when crypto-config is in use");
        }

        if cli.misc.crypto_config.is_none() {
            warn!("IC-Agent: crypto-config is missing, using anonymous principal");
        }

        let agent = create_agent(
            cli.misc.crypto_config.clone(),
            registry_client.clone(),
            cli.listen.listen_http_port_loopback,
        )
        .await?;

        if let Some(v) = &registry_client {
            // Fetch the NNS root key from the local registry snapshot
            let ver = v.get_latest_version();
            let nns_subnet_id = v
                .get_root_subnet_id(ver)
                .context("unable to get root subnet id")?
                .context("no root subnet")?;
            let root_key = v
                .get_threshold_signing_public_key_for_subnet(nns_subnet_id, ver)
                .context("unable to get root NNS key")?
                .context("no root NNS key")?;

            let der_encoded_root_key = threshold_sig_public_key_to_der(root_key)
                .context("failed to convert root NNS key to DER")?;

            agent.set_root_key(der_encoded_root_key);
        } else if let Some(v) = &cli.registry.registry_nns_pub_key_pem {
            // Set the root key if it was provided
            let root_key = parse_threshold_sig_key_from_pem_file(v)
                .context("failed to parse NNS public key")?;
            let der_encoded_root_key = threshold_sig_public_key_to_der(root_key)
                .context("failed to convert NNS key to DER")?;
            agent.set_root_key(der_encoded_root_key);
        }

        Some(agent)
    } else {
        None
    };

    // Caching
    let cache_state = if cli.cache.cache_size.is_some() {
        Some(Arc::new(
            CacheState::new(&cli.cache, &metrics_registry).context("unable to setup cache")?,
        ))
    } else {
        None
    };

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

    if let Some(v) = &generic_limiter {
        tasks.add("generic_limiter", v.clone());
    }

    // HTTP Logs Anonymization
    let anonymization_salt = Arc::new(ArcSwapOption::<Vec<u8>>::empty());

    // Proxy Router
    let proxy_router = Arc::new(ProxyRouter::new(
        http_client.clone(),
        routing_table.clone(),
        registry_snapshot.clone(),
        cli.health.health_subnets_alive_threshold,
        cli.health.health_nodes_per_subnet_alive_threshold,
    ));

    // Prepare Axum Router
    let router = setup_router(
        bouncer,
        generic_limiter,
        &cli,
        &metrics_registry,
        cache_state.clone(),
        anonymization_salt.clone(),
        proxy_router.clone(),
    );

    // HTTP server metrics
    let http_metrics = HttpServerMetrics::new(&metrics_registry);

    // HTTP server options
    let server_opts: ServerOptions = (&cli.http_server).into();

    // HTTP
    if let Some(v) = cli.listen.listen_http_port {
        let srv = bnhttp::ServerBuilder::new(router.clone())
            .listen_tcp(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), v))
            .with_options(server_opts)
            .with_metrics(http_metrics.clone())
            .build()
            .context("unable to build HTTP TCP server")?;

        tasks.add("server_http", Arc::new(srv));
    }

    // HTTP Unix Socket
    if let Some(v) = &cli.listen.listen_http_unix_socket {
        let srv = bnhttp::ServerBuilder::new(router.clone())
            .listen_unix(v.clone())
            .with_options(server_opts)
            .with_metrics(http_metrics.clone())
            .build()
            .context("unable to build HTTP Unix Socket server")?;

        tasks.add("server_http_unix", Arc::new(srv));
    }

    // HTTP loopback server.
    // Allows internal agents to work and be independent of the normal listening ports.
    // Probably we can find some way of working w/o a dedicated port (e.g. over memory) but it would be hard
    // to adapt HTTP clients for it.
    if agent.is_some() {
        let srv = bnhttp::ServerBuilder::new(router.clone())
            .listen_tcp(SocketAddr::new(
                Ipv4Addr::LOCALHOST.into(),
                cli.listen.listen_http_port_loopback,
            ))
            .with_options(server_opts)
            .with_metrics(http_metrics.clone())
            .build()
            .context("unable to build HTTP Loopback server")?;

        tasks.add("server_http_loopback", Arc::new(srv));
    }

    // HTTPS
    if cli.listen.listen_https_port.is_some() {
        let srv = setup_https(
            router,
            server_opts,
            &cli,
            &metrics_registry,
            http_metrics.clone(),
            &mut tasks,
        )
        .context("unable to setup HTTPS")?;

        tasks.add("server_https", Arc::new(srv));
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
    let metrics_server = bnhttp::ServerBuilder::new(metrics_router)
        .listen_tcp(cli.obs.obs_metrics_addr)
        .with_options(server_opts)
        .with_metrics(http_metrics)
        .build()
        .context("unable to build HTTP Metrics server")
        .unwrap();
    tasks.add("metrics_server", Arc::new(metrics_server));
    let metrics_runner = Arc::new(MetricsRunner::new(
        metrics_cache,
        metrics_registry.clone(),
        cache_state,
        registry_snapshot.clone(),
        proxy_router,
    ));
    tasks.add_interval("metrics_runner", metrics_runner, 5 * SECOND);

    // HTTP Logs Anonymization
    cli.obs
        .obs_log_anonymization_canister_id
        .and_then(|canister_id| {
            agent.as_ref().map(|agent| {
                let fetcher = Arc::new(AnonymizationSaltFetcher::new(
                    agent.clone(),
                    canister_id,
                    cli.obs.obs_log_anonymization_poll_interval,
                    anonymization_salt,
                    &metrics_registry,
                ));

                tasks.add("anonymization_salt_fetcher", fetcher.clone());

                fetcher
            })
        });

    // Start the tasks
    tasks.start();

    warn!("Started, waiting for shutdown signal");
    // Wait for Ctrl-C or SIGTERM
    let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate()).unwrap();
    select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }

    // Initiate shutdown
    warn!("Ctrl-C/SIGTERM received, shutting down");
    tasks.stop().await;
    warn!("Shutdown finished, exiting");

    Ok(())
}

type SignMessageId =
    Arc<dyn Fn(&MessageId) -> Result<Vec<u8>, Box<dyn std::error::Error>> + Send + Sync>;

/// Custom sender for the node, signing messages with its key.
struct NodeSender {
    /// DER encoded public key
    der_encoded_pub_key: Vec<u8>,
    /// Function that signs the message id
    sign: SignMessageId,
}

impl NodeSender {
    pub fn new(pub_key: PublicKey, sign: SignMessageId) -> Result<Self, String> {
        if pub_key.algorithm() != AlgorithmId::Ed25519 {
            return Err(format!(
                "Unsupported algorithm: {}",
                pub_key.algorithm().as_str_name()
            ));
        }

        let der_encoded_pub_key = ic_ed25519::PublicKey::convert_raw_to_der(&pub_key.key_value)
            .map_err(|err| err.to_string())?;

        Ok(Self {
            der_encoded_pub_key,
            sign,
        })
    }
}

impl Identity for NodeSender {
    fn sender(&self) -> Result<Principal, String> {
        Ok(Principal::self_authenticating(
            self.der_encoded_pub_key.as_slice(),
        ))
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        Some(self.der_encoded_pub_key.clone())
    }

    fn sign(&self, content: &EnvelopeContent) -> Result<Signature, String> {
        let msg = MessageId::from(*content.to_request_id());
        let signature =
            Some((self.sign)(&msg).map_err(|err| format!("Cannot create node signature: {err}"))?);
        let public_key = self.public_key();
        Ok(Signature {
            public_key,
            signature,
            delegations: None,
        })
    }
}

async fn create_identity(
    crypto_config: CryptoConfig,
    registry_client: Arc<dyn RegistryClient>,
) -> Result<Box<dyn Identity>, Error> {
    let crypto_component = tokio::task::spawn_blocking({
        let registry_client = registry_client.clone();

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
        let crypto_component = crypto_component.clone();

        move || {
            crypto_component
                .current_node_public_keys()
                .map_err(|e| anyhow!("failed to retrieve public key: {e:#}"))?
                .node_signing_public_key
                .context("missing node public key")
        }
    })
    .await??;

    // Custom Signer
    Ok(Box::new(
        NodeSender::new(
            public_key,
            Arc::new(move |msg: &MessageId| {
                #[allow(clippy::disallowed_methods)]
                let sig = tokio::task::block_in_place(|| {
                    crypto_component
                        .sign_basic(msg)
                        .map(|value| value.get().0)
                        .map_err(|err| anyhow!("failed to sign message: {err:?}"))
                })?;

                Ok(sig)
            }),
        )
        .map_err(|err| anyhow!(err))?,
    ))
}

async fn create_agent(
    crypto_config: Option<CryptoConfig>,
    registry_client: Option<Arc<dyn RegistryClient>>,
    port: u16,
) -> Result<Agent, Error> {
    let identity = match (crypto_config, registry_client) {
        (Some(v), Some(r)) => create_identity(v, r).await?,
        _ => Box::new(AnonymousIdentity),
    };

    let agent = Agent::builder()
        .with_url(format!("http://127.0.0.1:{port}"))
        .with_boxed_identity(identity)
        .build()?;

    Ok(agent)
}

/// Sets up registry-related stuff
async fn setup_registry(
    cli: &Cli,
    registry_snapshot: Arc<ArcSwapOption<RegistrySnapshot>>,
    persister: WithMetricsPersist<Persister>,
    http_client_check: Arc<dyn Client>,
    metrics_registry: &Registry,
    channel_snapshot_send: watch::Sender<Option<Arc<RegistrySnapshot>>>,
    channel_snapshot_recv: watch::Receiver<Option<Arc<RegistrySnapshot>>>,
    tasks: &mut TaskManager,
) -> Result<Arc<dyn RegistryClient>, Error> {
    let local_store = Arc::new(LocalStoreImpl::new(
        cli.registry.registry_local_store_path.clone().unwrap(),
    ));

    let registry_client = Arc::new(RegistryClientImpl::new(local_store, None));
    registry_client
        .fetch_and_start_polling()
        .context("failed to start registry client")?;

    // Snapshots
    let snapshotter = WithMetricsSnapshot(
        Snapshotter::new(
            registry_snapshot.clone(),
            channel_snapshot_send,
            registry_client.clone(),
            cli.registry.registry_min_version_age,
        ),
        MetricParamsSnapshot::new(metrics_registry),
    );
    tasks.add_interval("snapshotter", Arc::new(snapshotter), 5 * SECOND);

    // Start the health checking
    let checker = Checker::new(http_client_check, cli.health.health_check_timeout);
    let checker = WithMetricsCheck(checker, MetricParamsCheck::new(metrics_registry));
    let check_runner = CheckRunner::new(
        cli.health.health_max_height_lag,
        cli.health.health_check_interval,
        cli.health.health_update_interval,
        Arc::new(checker),
        Arc::new(persister),
        Mutex::new(channel_snapshot_recv),
    );
    tasks.add("check_runner", Arc::new(check_runner));

    if cli.registry.registry_disable_replicator {
        return Ok(());
    }

    // Notice no-op logger
    let logger = ic_logger::new_replica_logger(
        slog::Logger::root(tracing_slog::TracingSlogDrain, slog::o!()),
        &ic_config::logger::Config::default(),
    );

    let nns_pub_key = cli.registry.registry_nns_pub_key_pem.as_ref().map(|path| {
        parse_threshold_sig_key_from_pem_file(path).expect("failed to parse NNS public key")
    });

    let replicator = RegistryReplicator::new(
        logger,
        local_store_path,
        cli.registry.registry_nns_poll_interval,
        cli.registry.registry_nns_urls.clone(),
        nns_pub_key,
    )
    .await;

    let replicator_runner = RegistryReplicatorRunner::new(replicator);
    tasks.add("registry_replicator", Arc::new(replicator_runner));

    Ok(())
}

fn setup_tls_resolver_stub(cli: &cli::Tls) -> Result<Arc<dyn ResolvesServerCert>, Error> {
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

    let resolver = StubResolver::new(&cert, &key)?;
    Ok(Arc::new(resolver))
}

fn setup_tls_resolver_acme(
    cli: &cli::Tls,
    tasks: &mut TaskManager,
) -> Result<Arc<dyn ResolvesServerCert>, Error> {
    let path = cli
        .tls_acme_credentials_path
        .clone()
        .ok_or(anyhow!("ACME credentials path not specified"))?;

    let hostname = cli
        .tls_hostname
        .clone()
        .ok_or(anyhow!("hostname not specified"))?;

    let tls_config = if cli.tls_acme_disable_tls_cert_verification {
        let cfg = ic_bn_lib::rustls_acme::futures_rustls::rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoopServerCertVerifier::default()))
            .with_no_client_auth();

        Some(cfg)
    } else {
        None
    };

    let opts = AcmeAlpn::Opts::new(
        cli.tls_acme_url.clone(),
        vec![hostname],
        "mailto:boundary-nodes@dfinity.org".into(),
        path,
        tls_config,
    );

    let acme = Arc::new(AcmeAlpn::AcmeAlpn::new(opts));
    tasks.add("acme_alpn", acme.clone());

    Ok(acme)
}

/// Try to load the static resolver first, then ACME one.
/// This is needed for the integration tests where we cannot easily separate test/prod environments.
fn setup_tls_resolver(
    cli: &cli::Tls,
    tasks: &mut TaskManager,
) -> Result<Arc<dyn ResolvesServerCert>, Error> {
    warn!("TLS: Trying resolver: static files");
    match setup_tls_resolver_stub(cli) {
        Ok(v) => {
            warn!("TLS: static resolver loaded");
            return Ok(v);
        }

        Err(e) => warn!("TLS: unable to load static resolver: {e}"),
    }

    warn!(
        "TLS: Trying resolver: ACME ALPN-01 (URL: {})",
        cli.tls_acme_url
    );
    match setup_tls_resolver_acme(cli, tasks) {
        Ok(v) => {
            warn!("TLS: ACME resolver loaded");
            return Ok(v);
        }

        Err(e) => warn!("TLS: unable to load ACME resolver: {e}"),
    }

    bail!("TLS: no resolvers were able to load")
}

fn setup_https(
    router: Router,
    opts: ServerOptions,
    cli: &Cli,
    registry: &Registry,
    metrics: HttpServerMetrics,
    tasks: &mut TaskManager,
) -> Result<bnhttp::Server, Error> {
    use ic_bn_lib::tls;

    let resolver = setup_tls_resolver(&cli.tls, tasks).context("unable to setup TLS resolver")?;

    let tls_opts = TlsOptions {
        additional_alpn: vec![ALPN_ACME.to_vec()],
        sessions_count: cli.http_server.http_server_tls_session_cache_size,
        sessions_tti: cli.http_server.http_server_tls_session_cache_tti,
        ticket_lifetime: cli.http_server.http_server_tls_ticket_lifetime,
        tls_versions: vec![&rustls::version::TLS13],
    };

    let rustls_config = tls::prepare_server_config(tls_opts, resolver, registry);

    let server_https = bnhttp::ServerBuilder::new(router)
        .listen_tcp(SocketAddr::new(
            Ipv6Addr::UNSPECIFIED.into(),
            cli.listen.listen_https_port.unwrap(),
        ))
        .with_options(opts)
        .with_metrics(metrics)
        .with_rustls_config(rustls_config)
        .build()
        .context("unable to build HTTP TLS server")?;

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

/// Creates an Axum router that is ready to be served over HTTP
pub fn setup_router(
    bouncer: Option<Arc<bouncer::Bouncer>>,
    generic_limiter: Option<Arc<generic::GenericLimiter>>,
    cli: &Cli,
    metrics_registry: &Registry,
    cache_state: Option<Arc<CacheState>>,
    anonymization_salt: Arc<ArcSwapOption<Vec<u8>>>,
    proxy_router: Arc<ProxyRouter>,
) -> Router {
    // Init it early to avoid race conditions
    lazy_static::initialize(&UUID_REGEX);

    let (proxy, lookup, root_key, health) = (
        proxy_router.clone() as Arc<dyn Proxy>,
        proxy_router.clone() as Arc<dyn Lookup>,
        proxy_router.clone() as Arc<dyn RootKey>,
        proxy_router.clone() as Arc<dyn Health>,
    );

    let canister_handler = post(handlers::handle_canister).with_state(proxy.clone());
    let subnet_handler = post(handlers::handle_subnet).with_state(proxy.clone());

    let query_route = Router::new()
        .route(PATH_QUERY_V2, canister_handler.clone())
        .route(PATH_QUERY_V3, canister_handler.clone());

    let call_route = {
        let mut route = Router::new()
            .route(PATH_CALL_V2, canister_handler.clone())
            .route(PATH_CALL_V3, canister_handler.clone())
            .route(PATH_CALL_V4, canister_handler.clone());

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
        .route(PATH_STATUS, {
            get(handlers::status).with_state((root_key.clone(), health.clone()))
        })
        .layer(middleware::from_fn_with_state(
            HttpMetricParamsStatus::new(metrics_registry),
            metrics::metrics_middleware_status,
        ));

    let health_route = Router::new().route(PATH_HEALTH, {
        get(handlers::health).with_state(health.clone())
    });

    let middleware_geoip = option_layer(cli.misc.geoip_db.as_ref().map(|x| {
        middleware::from_fn_with_state(
            Arc::new(geoip::GeoIp::new(x).expect("unable to load GeoIP")),
            geoip::middleware,
        )
    }));

    // Create a PubSub broker for the logs subscription
    let logs_broker = cli.obs.obs_log_websocket.then(|| {
        Arc::new(
            BrokerBuilder::new()
                .with_buffer_size(cli.obs.obs_log_websocket_buffer)
                .with_idle_timeout(cli.obs.obs_log_websocket_idle_timeout)
                .with_max_subscribers(cli.obs.obs_log_websocket_max_subscribers_per_topic)
                .with_max_topics(cli.obs.obs_log_websocket_max_topics)
                .with_metric_registry(metrics_registry)
                .build(),
        )
    });

    let middleware_metrics = option_layer((!cli.obs.obs_disable_request_logging).then_some(
        middleware::from_fn_with_state(
            HttpMetricParams::new(
                metrics_registry,
                "http_request",
                cli.obs.obs_log_failed_requests_only,
                anonymization_salt,
                logs_broker.clone(),
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
    let middleware_subnet_lookup =
        middleware::from_fn_with_state(lookup.clone(), routes::lookup_subnet);
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
        .layer(middleware::from_fn(process::postprocess_response))
        .layer(middleware::from_fn(process::preprocess_request))
        .layer(load_shedder_latency_mw);

    let service_canister_read_call_query = ServiceBuilder::new()
        .layer(middleware::from_fn(validate::validate_request))
        .layer(middleware::from_fn(validate::validate_canister_request))
        .layer(common_service_layers.clone())
        .layer(middleware_subnet_lookup.clone())
        .layer(middleware_generic_limiter.clone())
        .layer(option_layer(cache_state.map(|x| {
            middleware::from_fn_with_state(x.clone(), cache_middleware)
        })))
        .layer(middleware_retry.clone());

    let service_subnet_read = ServiceBuilder::new()
        .layer(middleware::from_fn(validate::validate_request))
        .layer(middleware::from_fn(validate::validate_subnet_request))
        .layer(common_service_layers)
        .layer(middleware_subnet_lookup)
        .layer(middleware_generic_limiter)
        .layer(middleware_retry);

    let canister_read_state_route = Router::new()
        .route(PATH_READ_STATE_V2, canister_handler.clone())
        .route(PATH_READ_STATE_V3, canister_handler.clone());

    let canister_read_call_query_routes = query_route
        .merge(call_route)
        .merge(canister_read_state_route)
        .layer(service_canister_read_call_query);

    let subnet_read_state_route = Router::new()
        .route(PATH_SUBNET_READ_STATE_V2, subnet_handler.clone())
        .route(PATH_SUBNET_READ_STATE_V3, subnet_handler.clone())
        .layer(service_subnet_read);

    let mut router = canister_read_call_query_routes
        .merge(subnet_read_state_route)
        .merge(status_route)
        .merge(health_route);

    if let Some(v) = logs_broker {
        let state = Arc::new(LogsState::new(
            v,
            lookup,
            cli.obs.obs_log_websocket_max_subscribers_per_topic_per_ip,
        ));

        let logs_canister_router = Router::new()
            .route("/canister/{canister_id}", any(logs_canister))
            .layer(cors::layer());
        let logs_router = Router::new()
            .nest("/logs", logs_canister_router)
            .with_state(state);

        router = router.merge(logs_router);
    }

    router
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

#[cfg(test)]
mod test {
    use std::time::Instant;

    use clap::Parser;
    use http::StatusCode;
    use ic_bn_lib::tests::pebble::Env;

    use crate::cli::Cli;

    use super::*;

    /// Tests `ic-boundary` startup using ACME certificates obtained from Pebble
    #[tokio::test]
    async fn test_startup() {
        let pebble_env = Env::new().await;
        let acme_cache_path = tempfile::TempDir::new().unwrap();
        let acme_url = format!("https://{}/dir", pebble_env.addr_acme());

        let args = &[
            "",
            "--listen-https-port",
            "5001", // Pebble challenges on port 5001 by default
            "--tls-hostname",
            "foo.bar", // Pebble's DNS resolves any hostname to 127.0.0.1 by default
            "--tls-acme-url",
            &acme_url,
            "--tls-acme-credentials-path",
            acme_cache_path.path().to_str().unwrap(),
            "--tls-acme-disable-tls-cert-verification",
            "--registry-stub-replica",
            "127.0.0.1:1443", // Doesn't really matter
        ];

        let cli = Cli::parse_from(args);

        tokio::spawn(async move {
            if let Err(e) = main(cli).await {
                panic!("Unable to start ic-boundary: {e}");
            }
        });

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        // Poke ic-boundary until it issues the certificate
        let start = Instant::now();
        loop {
            let req = client.get("https://127.0.0.1:5001/health").build().unwrap();
            let res = client.execute(req).await;
            match res {
                Ok(v) => {
                    if v.status() == StatusCode::NO_CONTENT {
                        return;
                    }

                    println!("Status code incorrect: {}", v.status());
                }

                Err(e) => {
                    println!("Error: {e:#}");
                }
            };

            if start.elapsed() > Duration::from_secs(120) {
                break;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        panic!("Unable to query ic-boundary: timed out");
    }
}
