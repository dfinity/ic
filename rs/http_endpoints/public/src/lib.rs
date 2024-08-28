//! This is the entry point of the Internet Computer. This deals with
//! accepting HTTP connections, parsing messages and forwarding them to the
//! correct components.
//!
//! As much as possible the naming of structs in this module should match the
//! naming used in the [Interface
//! Specification](https://internetcomputer.org/docs/current/references/ic-interface-spec)
mod catch_up_package;
mod common;
mod dashboard;
mod health_status_refresher;
pub mod metrics;
mod pprof;
mod query;
mod read_state;
mod status;
mod tracing_flamegraph;

cfg_if::cfg_if! {
    if #[cfg(feature = "fuzzing_code")] {
        pub mod call;
    } else {
        mod call;
    }
}

pub use call::{call_v2, call_v3, IngressValidatorBuilder, IngressWatcher, IngressWatcherHandle};
pub use common::cors_layer;
pub use query::QueryServiceBuilder;
pub use read_state::canister::{CanisterReadStateService, CanisterReadStateServiceBuilder};
pub use read_state::subnet::SubnetReadStateServiceBuilder;

use crate::{
    catch_up_package::CatchUpPackageService,
    common::{
        get_root_threshold_public_key, make_plaintext_response, map_box_error_to_response,
        MAX_REQUEST_RECEIVE_TIMEOUT,
    },
    dashboard::DashboardService,
    health_status_refresher::HealthStatusRefreshLayer,
    metrics::{
        HttpHandlerMetrics, LABEL_HTTP_STATUS_CODE, LABEL_INSECURE, LABEL_IO_ERROR, LABEL_SECURE,
        LABEL_TIMEOUT_ERROR, LABEL_TLS_ERROR, LABEL_UNKNOWN, REQUESTS_LABEL_NAMES, STATUS_ERROR,
        STATUS_SUCCESS,
    },
    pprof::{PprofFlamegraphService, PprofHomeService, PprofProfileService},
    status::StatusService,
    tracing_flamegraph::TracingFlamegraphService,
};

use axum::{
    body::Body,
    error_handling::HandleErrorLayer,
    extract::{DefaultBodyLimit, MatchedPath, State},
    middleware::Next,
    response::Redirect,
    routing::get,
    Router,
};
use crossbeam::atomic::AtomicCell;
use http_body_util::{BodyExt, Full, LengthLimitError};
use hyper::{body::Incoming, Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use ic_async_utils::start_tcp_listener;
use ic_certification::validate_subnet_delegation_certificate;
use ic_config::http_handler::Config;
use ic_crypto_interfaces_sig_verification::IngressSigVerifier;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_crypto_tree_hash::{lookup_path, LabeledTree, Path};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_interfaces::{
    consensus_pool::ConsensusPoolCache,
    crypto::BasicSigner,
    execution_environment::{IngressFilterService, QueryExecutionService},
    ingress_pool::IngressPoolThrottler,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_logger::{debug, error, fatal, info, warn, ReplicaLogger};
use ic_metrics::{histogram_vec_timer::HistogramVecTimer, MetricsRegistry};
use ic_pprof::PprofCollector;
use ic_registry_client_helpers::{
    crypto::CryptoRegistry, node::NodeRegistry, node_operator::ConnectionEndpoint,
    subnet::SubnetRegistry,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_tracing::ReloadHandles;
use ic_types::{
    artifact::UnvalidatedArtifactMutation,
    malicious_flags::MaliciousFlags,
    messages::{
        Blob, Certificate, CertificateDelegation, HttpReadState, HttpReadStateContent,
        HttpReadStateResponse, HttpRequestEnvelope, MessageId, QueryResponseHash,
        ReplicaHealthStatus, SignedIngress,
    },
    time::expiry_time_from_now,
    Height, NodeId, SubnetId,
};
use rand::Rng;
use std::{
    convert::TryFrom,
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tempfile::NamedTempFile;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::mpsc::{Receiver, UnboundedSender},
    sync::watch,
    time::{sleep, timeout, Instant},
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tower::{limit::GlobalConcurrencyLimitLayer, BoxError, Service, ServiceBuilder};
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

const CONTENT_TYPE_CBOR: &str = "application/cbor";

/// [TLS Application-Layer Protocol Negotiation (ALPN) Protocol `HTTP/2 over TLS` ID][spec]
/// [spec]: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids)
const ALPN_HTTP2: &[u8; 2] = b"h2";

/// [TLS Application-Layer Protocol Negotiation (ALPN) Protocol `HTTP/1.1` ID][spec]
/// [spec]: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids)
const ALPN_HTTP1_1: &[u8; 8] = b"http/1.1";

/// To indicate a TLS handshake the first byte of the TLS record (also known as Content Type) is set to 22.
/// Defined in RFC 5246 for TLS 1.2 and RFC 8446 for TLS 1.3
const TLS_HANDHAKE_BYTES: u8 = 22;

#[derive(Debug, Clone, PartialEq)]
pub struct HttpError {
    pub status: StatusCode,
    pub message: String,
}

/// Struct that holds all endpoint services.
#[derive(Clone)]
struct HttpHandler {
    call_router: Router,
    call_v3_router: Router,
    query_router: Router,
    catchup_router: Router,
    dashboard_router: Router,
    status_router: Router,
    canister_read_state_router: Router,
    subnet_read_state_router: Router,
    pprof_home_router: Router,
    pprof_profile_router: Router,
    pprof_flamegraph_router: Router,
    tracing_flamegraph_router: Router,
}

// Crates a detached tokio blocking task that initializes the server (reading
// required state, etc).
fn start_server_initialization(
    config: Config,
    log: ReplicaLogger,
    metrics: HttpHandlerMetrics,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    rt_handle: tokio::runtime::Handle,
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
) {
    let rt_handle_clone = rt_handle.clone();
    rt_handle.spawn(async move {
        info!(log, "Initializing HTTP server...");
        // Sleep one second between retries, only log every 10th round.
        info!(log, "Waiting for certified state...");
        metrics
            .health_status_transitions_total
            .with_label_values(&[
                (health_status.load().as_ref()),
                (ReplicaHealthStatus::WaitingForCertifiedState.as_ref()),
            ])
            .inc();
        health_status.store(ReplicaHealthStatus::WaitingForCertifiedState);

        while common::get_latest_certified_state(state_reader.clone())
            .await
            .is_none()
        {
            info!(every_n_seconds => 10, log, "Certified state is not yet available...");
            sleep(Duration::from_secs(1)).await;
        }
        info!(log, "Certified state is now available.");
        // Fetch the delegation from the NNS for this subnet to be
        // able to issue certificates.
        health_status.store(ReplicaHealthStatus::WaitingForRootDelegation);
        let loaded_delegation = load_root_delegation(
            &config,
            &log,
            rt_handle_clone,
            subnet_id,
            nns_subnet_id,
            registry_client.as_ref(),
            tls_config.as_ref(),
        )
        .await;
        if let Some(delegation) = loaded_delegation {
            *delegation_from_nns.write().unwrap() = Some(delegation);
        }
        metrics
            .health_status_transitions_total
            .with_label_values(&[
                (health_status.load().as_ref()),
                (ReplicaHealthStatus::Healthy.as_ref()),
            ])
            .inc();
        health_status.store(ReplicaHealthStatus::Healthy);
        // TODO: NNS1-2024
        info!(log, "Ready for interaction.");
    });
}

fn create_port_file(path: PathBuf, port: u16) {
    // Figure out which port was assigned; write it to a temporary
    // file; and then rename the file to `path`.  We write to a
    // temporary file first to ensure that the write is atomic.  We
    // create the temporary file in the same directory as `path` as
    // `rename` between file systems in case of different
    // directories can fail.
    let dir = path.parent().unwrap_or_else(|| {
        panic!(
            "Could not get parent directory of port report file {}",
            path.display()
        )
    });
    let mut port_file = NamedTempFile::new_in(dir)
        .unwrap_or_else(|err| panic!("Could not open temporary port report file: {}", err));
    port_file
        .write_all(format!("{}", port).as_bytes())
        .unwrap_or_else(|err| {
            panic!(
                "Could not write to temporary port report file {}: {}",
                path.display(),
                err
            )
        });
    port_file.flush().unwrap_or_else(|err| {
        panic!(
            "Could not flush temporary port report file {}: {}",
            path.display(),
            err
        )
    });
    std::fs::rename(port_file, path.clone()).unwrap_or_else(|err| {
        panic!(
            "Could not rename temporary port report file {}: {}",
            path.display(),
            err
        )
    });
}

/// Creates HTTP server. The function returns only after a TCP listener is bound to a port.
///
/// The optional `delegation_from_nns` field is supposed to be used in tests
/// to provide a way to "fake" delegations received from the NNS subnet
/// without having to either mock all the related calls to the registry
/// or actually make the calls.
///
/// The unbounded channel, `terminal_state_ingress_messages`, is used to register the height
/// of the replicated state when each ingress message reaches a terminal state.
/// It is fine to use an unbounded channel as the the consumer, [`IngressWatcher`],
/// will be able to consume the messages at the same rate as they are produced.
#[allow(clippy::too_many_arguments)]
pub fn start_server(
    rt_handle: tokio::runtime::Handle,
    metrics_registry: &MetricsRegistry,
    config: Config,
    ingress_filter: IngressFilterService,
    query_execution_service: QueryExecutionService,
    ingress_throttler: Arc<RwLock<dyn IngressPoolThrottler + Send + Sync>>,
    ingress_tx: UnboundedSender<UnvalidatedArtifactMutation<SignedIngress>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    query_signer: Arc<dyn BasicSigner<QueryResponseHash> + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    tls_config: Arc<dyn TlsConfig + Send + Sync>,
    ingress_verifier: Arc<dyn IngressSigVerifier + Send + Sync>,
    node_id: NodeId,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    log: ReplicaLogger,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    subnet_type: SubnetType,
    malicious_flags: MaliciousFlags,
    delegation_from_nns: Option<CertificateDelegation>,
    pprof_collector: Arc<dyn PprofCollector>,
    tracing_handle: ReloadHandles,
    certified_height_watcher: watch::Receiver<Height>,
    completed_execution_messages_rx: Receiver<(MessageId, Height)>,
    enable_synchronous_call_handler_for_v3_endpoint: bool,
) {
    let listen_addr = config.listen_addr;
    info!(log, "Starting HTTP server...");

    // TODO(OR4-60): temporarily listen on [::] so that we accept both IPv4 and
    // IPv6 connections. This requires net.ipv6.bindv6only = 0. Revert this once
    // we have rolled out IPv6 in prometheus and ic_p8s_service_discovery.
    let mut addr = "[::]:8080".parse::<SocketAddr>().unwrap();
    addr.set_port(listen_addr.port());
    let tcp_listener = start_tcp_listener(addr, &rt_handle);
    let _enter = rt_handle.enter();
    if !AtomicCell::<ReplicaHealthStatus>::is_lock_free() {
        error!(log, "Replica health status uses locks instead of atomics.");
    }
    let metrics = HttpHandlerMetrics::new(metrics_registry);

    let delegation_from_nns = Arc::new(RwLock::new(delegation_from_nns));
    let health_status = Arc::new(AtomicCell::new(ReplicaHealthStatus::Starting));

    let ingress_filter = Arc::new(Mutex::new(ingress_filter));

    let call_handler = IngressValidatorBuilder::builder(
        log.clone(),
        node_id,
        subnet_id,
        registry_client.clone(),
        ingress_verifier.clone(),
        ingress_filter.clone(),
        ingress_throttler.clone(),
        ingress_tx.clone(),
    )
    .with_malicious_flags(malicious_flags.clone())
    .build();

    let (ingress_watcher_handle, _) = IngressWatcher::start(
        rt_handle.clone(),
        log.clone(),
        metrics.clone(),
        certified_height_watcher,
        completed_execution_messages_rx,
        CancellationToken::new(),
    );

    let call_router =
        call_v2::new_router(call_handler.clone(), Some(ingress_watcher_handle.clone()));

    let call_v3_router = if enable_synchronous_call_handler_for_v3_endpoint {
        call_v3::new_router(
            call_handler,
            ingress_watcher_handle,
            metrics.clone(),
            config.ingress_message_certificate_timeout_seconds,
            delegation_from_nns.clone(),
            state_reader.clone(),
        )
    } else {
        call_v3::new_asynchronous_call_service_router(
            call_handler.clone(),
            Some(ingress_watcher_handle.clone()),
        )
        // We only want to enforce the global concurrency limit for the asynchronous call handler.
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(map_box_error_to_response))
                .load_shed()
                .layer(GlobalConcurrencyLimitLayer::new(
                    config.max_call_concurrent_requests,
                )),
        )
    };

    let query_router = QueryServiceBuilder::builder(
        log.clone(),
        node_id,
        query_signer,
        registry_client.clone(),
        ingress_verifier.clone(),
        delegation_from_nns.clone(),
        query_execution_service,
    )
    .with_health_status(health_status.clone())
    .with_malicious_flags(malicious_flags.clone())
    .build_router();

    let canister_read_state_router = CanisterReadStateServiceBuilder::builder(
        log.clone(),
        state_reader.clone(),
        registry_client.clone(),
        ingress_verifier,
        delegation_from_nns.clone(),
    )
    .with_health_status(health_status.clone())
    .with_malicious_flags(malicious_flags)
    .build_router();

    let subnet_read_state_router =
        SubnetReadStateServiceBuilder::builder(delegation_from_nns.clone(), state_reader.clone())
            .with_health_status(health_status.clone())
            .build_router();
    let status_router = StatusService::build_router(
        log.clone(),
        nns_subnet_id,
        Arc::clone(&registry_client),
        Arc::clone(&health_status),
        state_reader.clone(),
    );
    let dashboard_router =
        DashboardService::new_router(config.clone(), subnet_type, state_reader.clone());
    let catchup_router = CatchUpPackageService::new_router(consensus_pool_cache.clone());

    let pprof_home_router = PprofHomeService::new_router();
    let pprof_profile_router = PprofProfileService::new_router(pprof_collector.clone());
    let pprof_flamegraph_router = PprofFlamegraphService::new_router(pprof_collector);

    let tracing_flamegraph_router = TracingFlamegraphService::build_router(tracing_handle);

    let health_status_refresher = HealthStatusRefreshLayer::new(
        log.clone(),
        metrics.clone(),
        Arc::clone(&health_status),
        consensus_pool_cache,
        state_reader.clone(),
    );

    start_server_initialization(
        config.clone(),
        log.clone(),
        metrics.clone(),
        subnet_id,
        nns_subnet_id,
        registry_client.clone(),
        state_reader,
        Arc::clone(&delegation_from_nns),
        Arc::clone(&health_status),
        rt_handle.clone(),
        tls_config.clone(),
    );

    let http_handler = HttpHandler {
        call_router,
        call_v3_router,
        query_router,
        status_router,
        catchup_router,
        dashboard_router,
        canister_read_state_router,
        subnet_read_state_router,
        pprof_home_router,
        pprof_profile_router,
        pprof_flamegraph_router,
        tracing_flamegraph_router,
    };
    let router = make_router(
        http_handler,
        config.clone(),
        metrics.clone(),
        health_status_refresher,
    );

    let port_file_path = config.port_file_path.clone();
    // If addr == 0, then a random port will be assigned. In this case it
    // is useful to report the randomly assigned port by writing it to a file.
    let local_addr = tcp_listener.local_addr().unwrap();
    if let Some(path) = port_file_path {
        create_port_file(path, local_addr.port());
    }

    let read_timeout = Duration::from_secs(config.connection_read_timeout_seconds);
    rt_handle.spawn(async move {
        loop {
            let (stream, _remote_addr) = tcp_listener.accept().await.unwrap();

            let router = router.clone();
            let tls_config = tls_config.clone();
            let log = log.clone();
            let registry_client = registry_client.clone();
            let metrics = metrics.clone();

            tokio::spawn(async move {
                metrics.connections_total.inc();

                let timer = Instant::now();
                // Set `NODELAY`
                if stream.set_nodelay(true).is_err() {
                    warn!(log, "Failed to set NODELAY option on tcp stream");
                }

                // Peek to know if it is TLS connection.
                let mut b = [0_u8; 1];
                match timeout(read_timeout, stream.peek(&mut b)).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) => {
                        metrics
                            .connection_setup_duration
                            .with_label_values(&[STATUS_ERROR, LABEL_IO_ERROR])
                            .observe(timer.elapsed().as_secs_f64());
                        metrics.closed_connections_total.inc();
                        return;
                    }
                    Err(_) => {
                        metrics
                            .connection_setup_duration
                            .with_label_values(&[STATUS_ERROR, LABEL_TIMEOUT_ERROR])
                            .observe(timer.elapsed().as_secs_f64());
                        metrics.closed_connections_total.inc();
                        return;
                    }
                }
                let mut stream = tokio_io_timeout::TimeoutStream::new(stream);
                stream.set_read_timeout(Some(read_timeout));
                let stream = Box::pin(stream);

                if b[0] == TLS_HANDHAKE_BYTES {
                    let _timer = metrics
                        .connection_duration
                        .with_label_values(&[LABEL_SECURE])
                        .start_timer();
                    let mut server_config = match tls_config
                        .server_config_without_client_auth(registry_client.get_latest_version())
                    {
                        Ok(c) => c,
                        Err(err) => {
                            warn!(log, "Failed to get server config from crypto {err}");
                            metrics.closed_connections_total.inc();
                            return;
                        }
                    };
                    server_config.alpn_protocols = vec![ALPN_HTTP2.to_vec(), ALPN_HTTP1_1.to_vec()];
                    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

                    match tls_acceptor.accept(stream).await {
                        Ok(stream) => {
                            metrics
                                .connection_setup_duration
                                .with_label_values(&[STATUS_SUCCESS, LABEL_SECURE])
                                .observe(timer.elapsed().as_secs_f64());
                            if let Err(err) =
                                serve_http(stream, router, config.http_max_concurrent_streams).await
                            {
                                warn!(log, "failed to serve connection: {err}");
                            }
                        }
                        Err(_) => {
                            metrics
                                .connection_setup_duration
                                .with_label_values(&[STATUS_ERROR, LABEL_TLS_ERROR])
                                .observe(timer.elapsed().as_secs_f64());
                        }
                    }
                } else {
                    let _timer = metrics
                        .connection_duration
                        .with_label_values(&[LABEL_INSECURE])
                        .start_timer();
                    metrics
                        .connection_setup_duration
                        .with_label_values(&[STATUS_SUCCESS, LABEL_INSECURE])
                        .observe(timer.elapsed().as_secs_f64());
                    if let Err(err) =
                        serve_http(stream, router, config.http_max_concurrent_streams).await
                    {
                        warn!(log, "failed to serve connection: {err}");
                    }
                };

                metrics.closed_connections_total.inc();
            });
        }
    });
}

async fn serve_http<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    stream: S,
    router: Router,
    max_concurrent_streams: u32,
) -> Result<(), BoxError> {
    let stream = TokioIo::new(stream);
    let hyper_service =
        hyper::service::service_fn(move |request: Request<Incoming>| router.clone().call(request));
    hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .http2()
        .max_concurrent_streams(max_concurrent_streams)
        .serve_connection_with_upgrades(stream, hyper_service)
        .await
}

fn make_router(
    http_handler: HttpHandler,
    config: Config,
    metrics: HttpHandlerMetrics,
    health_status_refresher: HealthStatusRefreshLayer,
) -> Router {
    let pprof_concurrency_limiter =
        GlobalConcurrencyLimitLayer::new(config.max_pprof_concurrent_requests);

    let base_router = Router::new()
        // TODO this is 303 instead of 302
        .route(
            "/",
            get(|| async { Redirect::to(DashboardService::route()) }),
        )
        .route(
            "/_/",
            get(|| async { Redirect::to(DashboardService::route()) }),
        )
        .fallback(|| async {
            make_plaintext_response(StatusCode::NOT_FOUND, "Endpoint not found.".to_string())
        });

    let final_router = base_router
        .merge(
            http_handler.status_router.layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(map_box_error_to_response))
                    .load_shed()
                    .layer(GlobalConcurrencyLimitLayer::new(
                        config.max_status_concurrent_requests,
                    )),
            ),
        )
        .merge(
            http_handler.call_router.layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(map_box_error_to_response))
                    .load_shed()
                    .layer(GlobalConcurrencyLimitLayer::new(
                        config.max_call_concurrent_requests,
                    )),
            ),
        )
        .merge(http_handler.call_v3_router)
        .merge(
            http_handler.query_router.layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(map_box_error_to_response))
                    .load_shed()
                    .layer(GlobalConcurrencyLimitLayer::new(
                        config.max_query_concurrent_requests,
                    )),
            ),
        )
        .merge(
            http_handler.subnet_read_state_router.layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(map_box_error_to_response))
                    .load_shed()
                    .layer(GlobalConcurrencyLimitLayer::new(
                        config.max_read_state_concurrent_requests,
                    )),
            ),
        )
        .merge(
            http_handler.canister_read_state_router.layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(map_box_error_to_response))
                    .load_shed()
                    .layer(GlobalConcurrencyLimitLayer::new(
                        config.max_read_state_concurrent_requests,
                    )),
            ),
        )
        .merge(
            http_handler.catchup_router.layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(map_box_error_to_response))
                    .load_shed()
                    .layer(GlobalConcurrencyLimitLayer::new(
                        config.max_catch_up_package_concurrent_requests,
                    )),
            ),
        )
        .merge(
            http_handler.dashboard_router.layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(map_box_error_to_response))
                    .load_shed()
                    .layer(GlobalConcurrencyLimitLayer::new(
                        config.max_dashboard_concurrent_requests,
                    )),
            ),
        )
        .merge(
            http_handler.pprof_home_router.layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(map_box_error_to_response))
                    .load_shed()
                    .layer(pprof_concurrency_limiter.clone()),
            ),
        )
        .merge(
            http_handler.pprof_flamegraph_router.layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(map_box_error_to_response))
                    .load_shed()
                    .layer(pprof_concurrency_limiter.clone()),
            ),
        )
        .merge(
            http_handler.pprof_profile_router.layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(map_box_error_to_response))
                    .load_shed()
                    .layer(pprof_concurrency_limiter.clone()),
            ),
        )
        .merge(
            http_handler.tracing_flamegraph_router.layer(
                ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(map_box_error_to_response))
                    .load_shed()
                    .layer(GlobalConcurrencyLimitLayer::new(
                        config.max_tracing_flamegraph_concurrent_requests,
                    )),
            ),
        );

    final_router.layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(HandleErrorLayer::new(map_box_error_to_response))
            .layer(health_status_refresher.clone())
            .load_shed()
            .timeout(Duration::from_secs(config.request_timeout_seconds))
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(metrics),
                collect_timer_metric,
            ))
            // Disable default limit since apply a request limit to all routes.
            .layer(DefaultBodyLimit::disable())
            .layer(RequestBodyLimitLayer::new(
                config.max_request_size_bytes as usize,
            ))
            .layer(cors_layer()),
    )
}

async fn verify_cbor_content_header(
    request: axum::extract::Request,
    next: Next,
) -> axum::response::Response {
    if !request
        .headers()
        .get_all(http::header::CONTENT_TYPE)
        .iter()
        .any(|value| {
            if let Ok(v) = value.to_str() {
                return v.to_lowercase() == CONTENT_TYPE_CBOR;
            }
            false
        })
    {
        return make_plaintext_response(
            StatusCode::BAD_REQUEST,
            format!("Unexpected content-type, expected {}.", CONTENT_TYPE_CBOR),
        );
    }

    next.run(request).await
}

async fn collect_timer_metric(
    State(metrics): State<Arc<HttpHandlerMetrics>>,
    request: axum::extract::Request,
    next: Next,
) -> axum::response::Response {
    use http_body::Body;

    let path = if let Some(matched_path) = request.extensions().get::<MatchedPath>() {
        matched_path.as_str().to_owned()
    } else {
        request.uri().path().to_owned()
    };

    let http_version = format!("{:?}", request.version());

    metrics
        .request_http_version_counts
        .with_label_values(&[&http_version])
        .inc();

    metrics
        .request_body_size_bytes
        .with_label_values(&[&path, LABEL_UNKNOWN])
        .observe(request.body().size_hint().lower() as f64);

    let request_timer = HistogramVecTimer::start_timer(
        metrics.requests.clone(),
        &REQUESTS_LABEL_NAMES,
        [&path, LABEL_UNKNOWN],
    );

    let resp = next.run(request).await;

    let status = resp.status();
    // This is a workaround for `StatusCode::as_str()` not returning a `&'static
    // str`. It ensures `request_timer` is dropped before `status`.
    let mut timer = request_timer;
    timer.set_label(LABEL_HTTP_STATUS_CODE, status.as_str());

    metrics
        .response_body_size_bytes
        .with_label_values(&[&path])
        .observe(resp.body().size_hint().lower() as f64);
    resp
}

// Fetches a delegation from the NNS subnet to allow this subnet to issue
// certificates on its behalf. On the NNS subnet this method is a no-op.
async fn load_root_delegation(
    config: &Config,
    log: &ReplicaLogger,
    rt_handle: tokio::runtime::Handle,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    tls_config: &(dyn TlsConfig + Send + Sync),
) -> Option<CertificateDelegation> {
    if subnet_id == nns_subnet_id {
        info!(log, "On the NNS subnet. Skipping fetching the delegation.");
        // On the NNS subnet. No delegation needs to be fetched.
        return None;
    }

    let mut fetching_root_delagation_attempts = 0;

    loop {
        fetching_root_delagation_attempts += 1;
        info!(
            log,
            "Fetching delegation from the nns subnet. Attempts: {}.",
            fetching_root_delagation_attempts
        );

        let backoff = Duration::from_secs(rand::thread_rng().gen_range(1..15));

        match try_fetch_delegation_from_nns(
            config,
            log,
            &rt_handle,
            &subnet_id,
            &nns_subnet_id,
            registry_client,
            tls_config,
        )
        .await
        {
            Ok(delegation) => return Some(delegation),
            Err(err) => {
                warn!(
                    log,
                    "Fetching delegation from nns subnet failed. Retrying again in {} seconds...\n\
                        Error received: {}",
                    backoff.as_secs(),
                    err
                );
            }
        }

        // Fetching the NNS delegation failed. Do a random backoff and try again.
        sleep(backoff).await;
    }
}

/// Tries to fetch a delegation from the NNS subnet.
/// Returns a BoxError if any step of the process fails.
async fn try_fetch_delegation_from_nns(
    config: &Config,
    log: &ReplicaLogger,
    rt_handle: &tokio::runtime::Handle,
    subnet_id: &SubnetId,
    nns_subnet_id: &SubnetId,
    registry_client: &dyn RegistryClient,
    tls_config: &(dyn TlsConfig + Send + Sync),
) -> Result<CertificateDelegation, BoxError> {
    let (peer_id, node) =
        match get_random_node_from_nns_subnet(registry_client, *nns_subnet_id).await {
            Ok(node_topology) => node_topology,
            Err(err) => {
                fatal!(
                    log,
                    "Could not find a node from the root subnet to talk to. Error :{}",
                    err
                );
            }
        };

    let envelope = HttpRequestEnvelope {
        content: HttpReadStateContent::ReadState {
            read_state: HttpReadState {
                sender: Blob(vec![4]),
                paths: vec![
                    Path::new(vec![
                        b"subnet".into(),
                        subnet_id.get().into(),
                        b"public_key".into(),
                    ]),
                    Path::new(vec![
                        b"subnet".into(),
                        subnet_id.get().into(),
                        b"canister_ranges".into(),
                    ]),
                ],
                ingress_expiry: expiry_time_from_now().as_nanos_since_unix_epoch(),
                nonce: None,
            },
        },
        sender_pubkey: None,
        sender_sig: None,
        sender_delegation: None,
    };

    let body = serde_cbor::ser::to_vec(&envelope).unwrap();

    let registry_version = registry_client.get_latest_version();

    let ip_addr = node.ip_addr.parse().unwrap();

    let addr = SocketAddr::new(ip_addr, node.port as u16);

    let tls_client_config = tls_config
        .client_config(peer_id, registry_version)
        .map_err(|err| format!("Retrieving TLS client config failed: {:?}.", err))?;

    let tcp_stream: TcpStream = TcpStream::connect(addr)
        .await
        .map_err(|err| format!("Could not connect to node {}. {:?}.", addr, err))?;

    let tls_connector = TlsConnector::from(Arc::new(tls_client_config));
    let irrelevant_domain = "domain.is-irrelevant-as-hostname-verification-is.disabled";
    let tls_stream = tls_connector
        .connect(
            irrelevant_domain
                .try_into()
                // TODO: ideally the expect should run at compile time
                .expect("failed to create domain"),
            tcp_stream,
        )
        .await
        .map_err(|err| {
            format!(
                "Could not establish TLS stream to node {}. {:?}.",
                addr, err
            )
        })?;

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)).await?;

    let log_clone = log.clone();

    // Spawn a task to poll the connection, driving the HTTP state
    rt_handle.spawn(async move {
        if let Err(err) = connection.await {
            warn!(log_clone, "Polling connection failed: {:?}.", err);
        }
    });

    // any effective canister id can be used when invoking read_state here
    let uri = "/api/v2/canister/aaaaa-aa/read_state";

    info!(
        log,
        "Attempt to fetch HTTPS delegation from root subnet node with addr = `{}`, uri = `{}`.",
        addr,
        uri
    );

    let nns_request = Request::builder()
        .method(hyper::Method::POST)
        .uri(uri)
        .header(hyper::header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
        .body(Body::new(Full::from(body).map_err(BoxError::from)))?;

    let raw_response_res = request_sender.send_request(nns_request).await?;

    let raw_response = match timeout(
        MAX_REQUEST_RECEIVE_TIMEOUT,
        http_body_util::Limited::new(
            raw_response_res.into_body(),
            config.max_delegation_certificate_size_bytes as usize,
        )
        .collect(),
    )
    .await
    {
        Ok(Ok(c)) => c.to_bytes(),
        Ok(Err(e)) if e.is::<LengthLimitError>() => {
            return Err(format!(
                "Http body exceeds size limit of {} bytes.",
                config.max_delegation_certificate_size_bytes
            )
            .into())
        }
        Ok(Err(e)) => return Err(format!("Failed to read body from connection: {}", e).into()),
        Err(e) => {
            return Err(format!(
                "Timeout of {}s reached while receiving http body: {}",
                MAX_REQUEST_RECEIVE_TIMEOUT.as_secs(),
                e
            )
            .into())
        }
    };

    debug!(log, "Response from nns subnet: {:?}", raw_response);

    let response: HttpReadStateResponse = serde_cbor::from_slice(&raw_response)?;

    let parsed_delegation: Certificate = serde_cbor::from_slice(&response.certificate)
        .map_err(|e| format!("failed to parse delegation certificate: {}", e))?;

    let labeled_tree = LabeledTree::try_from(parsed_delegation.tree)
        .map_err(|e| format!("Invalid hash tree in the delegation certificate: {:?}", e))?;

    let own_public_key_from_registry = match registry_client
        .get_threshold_signing_public_key_for_subnet(*subnet_id, registry_version)
    {
        Ok(Some(pk)) => Ok(pk),
        Ok(None) => Err(format!(
            "subnet {} public key from registry is empty",
            subnet_id
        )),
        Err(err) => Err(format!(
            "subnet {} public key could not be extracted from registry: {:?}",
            subnet_id, err
        )),
    }?;

    match lookup_path(
        &labeled_tree,
        &[b"subnet", subnet_id.get_ref().as_ref(), b"public_key"],
    ) {
        Some(LabeledTree::Leaf(pk_bytes)) => {
            let public_key_from_certificate = parse_threshold_sig_key_from_der(pk_bytes)?;

            if public_key_from_certificate != own_public_key_from_registry {
                Err(format!(
                    "invalid public key type in certificate for subnet {}",
                    subnet_id
                ))
            } else {
                Ok(())
            }
        }
        _ => Err(format!(
            "subnet {} public key could not be extracted from certificate",
            subnet_id
        )),
    }?;

    let root_threshold_public_key =
        get_root_threshold_public_key(log, registry_client, registry_version, nns_subnet_id)
            .ok_or("could not retrieve threshold root public key from registry")?;

    validate_subnet_delegation_certificate(
        &response.certificate,
        subnet_id,
        &root_threshold_public_key,
    )
    .map_err(|err| format!("invalid subnet delegation certificate: {:?} ", err))?;

    let delegation = CertificateDelegation {
        subnet_id: Blob(subnet_id.get().to_vec()),
        certificate: response.certificate,
    };

    info!(log, "Setting NNS delegation to: {:?}", delegation);
    Ok(delegation)
}

async fn get_random_node_from_nns_subnet(
    registry_client: &dyn RegistryClient,
    nns_subnet_id: SubnetId,
) -> Result<(NodeId, ConnectionEndpoint), String> {
    use rand::seq::SliceRandom;

    let nns_nodes = match registry_client
        .get_node_ids_on_subnet(nns_subnet_id, registry_client.get_latest_version())
    {
        Ok(Some(nns_nodes)) => Ok(nns_nodes),
        Ok(None) => Err("No nns nodes found.".to_string()),
        Err(err) => Err(format!("Failed to get nns nodes from registry: {}", err)),
    }?;

    // Randomly choose a node from the nns subnet.
    let mut rng = rand::thread_rng();
    let nns_node = nns_nodes.choose(&mut rng).ok_or(format!(
        "Failed to choose random nns node. NNS node list: {:?}",
        nns_nodes
    ))?;
    match registry_client.get_node_record(*nns_node, registry_client.get_latest_version()) {
        Ok(Some(node)) => Ok((*nns_node, node.http.ok_or("No http endpoint for node")?)),
        Ok(None) => Err(format!(
            "No transport info found for nns node. {}",
            nns_node
        )),
        Err(err) => Err(format!(
            "failed to get node record for nns node {}. Err: {}",
            nns_node, err
        )),
    }
}

#[cfg(test)]
mod tests {
    use crate::read_state::subnet::SubnetReadStateService;
    use bytes::Bytes;
    use futures_util::{future::select_all, stream::pending, FutureExt};
    use http::{
        header::{
            ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
            ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE,
        },
        HeaderName, HeaderValue, Method,
    };
    use http_body_util::Empty;
    use ic_interfaces_mocks::consensus_pool::MockConsensusPoolCache;
    use ic_interfaces_state_manager_mocks::MockStateManager;
    use ic_logger::replica_logger::no_op_logger;
    use ic_types::{CanisterId, Height};
    use std::convert::Infallible;
    use tower::ServiceExt;

    use crate::{common::Cbor, query::QueryService};

    use super::*;

    fn empty_cbor() -> Bytes {
        Bytes::from(serde_cbor::to_vec(&()).unwrap())
    }

    fn dummy_router(config: Config) -> Router {
        async fn dummy(_body: Bytes) -> String {
            "success".to_string()
        }
        async fn dummy_cbor(_body: Cbor<()>) -> String {
            "success".to_string()
        }
        let http_handler = HttpHandler {
            call_router: Router::new().route(call_v2::route(), axum::routing::post(dummy)),
            call_v3_router: Router::new().route(call_v3::route(), axum::routing::post(dummy)),
            query_router: Router::new()
                .route(QueryService::route(), axum::routing::post(dummy_cbor)),
            catchup_router: Router::new().route(
                CatchUpPackageService::route(),
                axum::routing::post(dummy_cbor),
            ),
            dashboard_router: Router::new()
                .route(DashboardService::route(), axum::routing::get(dummy)),
            status_router: Router::new().route(StatusService::route(), axum::routing::get(dummy)),
            canister_read_state_router: Router::new().route(
                CanisterReadStateService::route(),
                axum::routing::post(dummy),
            ),
            subnet_read_state_router: Router::new()
                .route(SubnetReadStateService::route(), axum::routing::post(dummy)),
            pprof_home_router: Router::new()
                .route(PprofHomeService::route(), axum::routing::get(dummy)),
            pprof_profile_router: Router::new()
                .route(PprofProfileService::route(), axum::routing::get(dummy)),
            pprof_flamegraph_router: Router::new()
                .route(PprofFlamegraphService::route(), axum::routing::get(dummy)),
            tracing_flamegraph_router: Router::new()
                .route(TracingFlamegraphService::route(), axum::routing::get(dummy)),
        };

        let metrics = HttpHandlerMetrics::new(&MetricsRegistry::default());

        let mut state_manager = MockStateManager::new();
        state_manager
            .expect_latest_certified_height()
            .return_const(Height::from(1));

        let mut consensus_pool_cache = MockConsensusPoolCache::new();
        consensus_pool_cache
            .expect_is_replica_behind()
            .return_const(false);

        make_router(
            http_handler,
            config,
            metrics.clone(),
            HealthStatusRefreshLayer::new(
                no_op_logger(),
                metrics,
                Arc::new(AtomicCell::new(ReplicaHealthStatus::Healthy)),
                Arc::new(consensus_pool_cache),
                Arc::new(state_manager),
            ),
        )
    }

    /// Request that takes forever to read.
    fn infinite_request(
        uri: String,
        method: Method,
        header: Option<(HeaderName, &str)>,
    ) -> Request<Body> {
        let mut r = Request::builder()
            .uri(uri)
            .method(method)
            .body(Body::from_stream(pending::<Result<Bytes, Infallible>>()))
            .unwrap();
        if let Some((k, v)) = header {
            r.headers_mut().append(k, HeaderValue::from_str(v).unwrap());
        }
        r
    }

    // Verify that ReplicatedStateHealth is represented as an atomic by crossbeam.
    #[test]
    fn test_replica_state_atomic() {
        assert!(AtomicCell::<ReplicaHealthStatus>::is_lock_free());
    }

    #[tokio::test]
    async fn payload_too_large_without_content_length() {
        let router = dummy_router(Config {
            max_request_size_bytes: 100,
            ..Default::default()
        });
        let req = Request::builder()
            .uri("/_/catch_up_package")
            .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .method(hyper::Method::POST)
            .body(Body::new(Full::from(vec![0; 1000])))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn payload_too_large_with_content_length() {
        let router = dummy_router(Config {
            max_request_size_bytes: 100,
            ..Default::default()
        });
        let req = Request::builder()
            .uri("/_/catch_up_package")
            .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .method(hyper::Method::POST)
            .header("content-length", "1000")
            .body(Body::new(Full::from(vec![0; 1000])))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn invalid_method_for_existing_endpoint() {
        let router = dummy_router(Config::default());
        let req = Request::builder()
            .uri("/_/catch_up_package")
            .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .method(hyper::Method::GET)
            .body(Body::new(Empty::new()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn pre_flight_cors() {
        let router = dummy_router(Config::default());
        let req = Request::builder()
            .uri("/_/catch_up_package")
            .method(hyper::Method::OPTIONS)
            .body(Body::new(Empty::new()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert!(resp.headers().contains_key(ACCESS_CONTROL_ALLOW_HEADERS));
        assert!(resp.headers().contains_key(ACCESS_CONTROL_ALLOW_ORIGIN));
        assert!(resp.headers().contains_key(ACCESS_CONTROL_ALLOW_METHODS));
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn pre_flight_cors_fallback_path() {
        let router = dummy_router(Config::default());
        let req = Request::builder()
            .uri("/_/sdfsfdsfd")
            .method(hyper::Method::OPTIONS)
            .body(Body::new(Empty::new()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert!(resp.headers().contains_key(ACCESS_CONTROL_ALLOW_HEADERS));
        assert!(resp.headers().contains_key(ACCESS_CONTROL_ALLOW_ORIGIN));
        assert!(resp.headers().contains_key(ACCESS_CONTROL_ALLOW_METHODS));
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn origin_cors() {
        let router = dummy_router(Config::default());
        let req = Request::builder()
            .uri(format!("/api/v2/canister/{}/query", CanisterId::ic_00()))
            .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .method(hyper::Method::POST)
            .body(Body::new(Full::new(empty_cbor())))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert!(resp.headers().contains_key(ACCESS_CONTROL_ALLOW_ORIGIN));
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn non_existing_endpoint() {
        let router = dummy_router(Config::default());
        let req = Request::builder()
            .uri("/_/idontexist")
            .method(hyper::Method::GET)
            .body(Body::new(Empty::new()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn enforce_cbor_header() {
        let router = dummy_router(Config::default());
        let req = Request::builder()
            .uri("/_/catch_up_package")
            .method(hyper::Method::POST)
            .body(Body::new(Empty::new()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn request_timeout() {
        let router = dummy_router(Config {
            request_timeout_seconds: 1,
            ..Default::default()
        });
        let req = infinite_request(
            "/_/catch_up_package".to_string(),
            Method::POST,
            Some((CONTENT_TYPE, CONTENT_TYPE_CBOR)),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn concurrent_request_limiter_cup() {
        let router = dummy_router(Config {
            max_catch_up_package_concurrent_requests: 10,
            ..Default::default()
        });
        let futs = (0..11)
            .map(|_| {
                let req = infinite_request(
                    "/_/catch_up_package".to_string(),
                    Method::POST,
                    Some((CONTENT_TYPE, CONTENT_TYPE_CBOR)),
                );
                let router = router.clone();
                async { router.oneshot(req).await.unwrap() }.boxed()
            })
            .collect::<Vec<_>>();

        assert_eq!(
            select_all(futs).await.0.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn concurrent_request_limiter_query() {
        let router = dummy_router(Config {
            max_query_concurrent_requests: 10,
            ..Default::default()
        });
        let futs = (0..11)
            .map(|_| {
                let req = infinite_request(
                    format!("/api/v2/canister/{}/query", CanisterId::ic_00()),
                    Method::POST,
                    Some((CONTENT_TYPE, CONTENT_TYPE_CBOR)),
                );
                let router = router.clone();
                async { router.oneshot(req).await.unwrap() }.boxed()
            })
            .collect::<Vec<_>>();

        assert_eq!(
            select_all(futs).await.0.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn concurrent_request_limiter_not_all_blocked() {
        let router = dummy_router(Config {
            max_query_concurrent_requests: 10,
            ..Default::default()
        });
        let futs = (0..11)
            .map(|_| {
                let req = infinite_request(
                    format!("/api/v2/canister/{}/query", CanisterId::ic_00()),
                    Method::POST,
                    Some((CONTENT_TYPE, CONTENT_TYPE_CBOR)),
                );
                let router = router.clone();
                async { router.oneshot(req).await.unwrap() }.boxed()
            })
            .collect::<Vec<_>>();

        assert_eq!(
            select_all(futs).await.0.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        let req = Request::builder()
            .uri("/_/catch_up_package")
            .header(CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .method(hyper::Method::POST)
            .body(Body::new(Full::new(empty_cbor())))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
