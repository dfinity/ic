/// This is the entry point of the Internet Computer. This deals with
/// accepting HTTP connections, parsing messages and forwarding them to the
/// correct components.
///
/// As much as possible the naming of structs in this module should match the
/// naming used in the [Interface
/// Specification](https://sdk.dfinity.org/docs/interface-spec/index.html)
mod body;
mod call;
mod catch_up_package;
mod common;
mod dashboard;
mod metrics;
mod pprof;
mod query;
mod read_state;
mod status;
mod types;

use crate::{
    body::BodyReceiverLayer,
    call::CallService,
    catch_up_package::CatchUpPackageService,
    common::{get_cors_headers, map_box_error_to_response},
    dashboard::DashboardService,
    metrics::{
        LABEL_REQUEST_TYPE, LABEL_STATUS, LABEL_TYPE, REQUESTS_LABEL_NAMES, REQUESTS_NUM_LABELS,
    },
    query::QueryService,
    read_state::ReadStateService,
    status::StatusService,
    types::*,
};
use hyper::{server::conn::Http, Body, Request, Response, StatusCode};
use ic_async_utils::ObservableCountingSemaphore;
use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_crypto_tree_hash::{lookup_path, LabeledTree, Path};
use ic_interfaces::{
    consensus_pool::ConsensusPoolCache,
    crypto::IngressSigVerifier,
    execution_environment::{IngressFilterService, QueryExecutionService},
    p2p::IngressIngestionService,
    registry::RegistryClient,
    state_manager::StateReader,
};
use ic_logger::{debug, error, fatal, info, warn, ReplicaLogger};
use ic_metrics::{histogram_vec_timer::HistogramVecTimer, MetricsRegistry};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{NodeTopology, ReplicatedState};
use ic_types::{
    canonical_error::{invalid_argument_error, unknown_error, CanonicalError},
    malicious_flags::MaliciousFlags,
    messages::{
        Blob, Certificate, CertificateDelegation, HttpReadState, HttpReadStateContent,
        HttpReadStateResponse, HttpRequestEnvelope, ReplicaHealthStatus,
    },
    time::current_time_and_expiry_time,
    SubnetId,
};
use metrics::HttpHandlerMetrics;
use rand::Rng;
use std::{
    convert::TryFrom,
    io::{Error, ErrorKind, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
    time::Duration,
};
use tempfile::NamedTempFile;
use tokio::{
    net::{TcpListener, TcpStream},
    time::{sleep, timeout, Instant},
};
use tower::{
    load_shed::LoadShed, service_fn, util::BoxService, BoxError, Service, ServiceBuilder,
    ServiceExt,
};

// Constants defining the limits of the HttpHandler.

// The http handler should apply backpresure when we lack a particular resources
// which is purely HttpHandler related (e.g. connections, file descritors).
//
// Current mechanisms for constrained resources include:
//
// 1. File descriptors. The limit can be checked by 'process_max_fds'
// Prometheus metric. The number of file descriptors used by the crate is
// controlled by 'MAX_OUTSTANDING_CONNECTIONS'.
//
// 2. Lock contention. Currently we don't use lock-free data structures
// (e.g. StateManager, RegistryClient), hence we can observe lock contention.
// 'MAX_REQUESTS_PER_SECOND_PER_CONNECTION' is used to control the risk of
// running into contention. A resonable value can be derived by looking what are
// the latencies for operations that hold locks (e.g. methods on the
// RegistryClient and StateManager).

// In the HttpHandler we can have at most 'MAX_OUTSTANDING_CONNECTIONS'
// live TCP connections. If we are at the limit, we won't
// accept new TCP connections.
const MAX_OUTSTANDING_CONNECTIONS: usize = 20000;

// Sets the SETTINGS_MAX_CONCURRENT_STREAMS option for HTTP2 connections.
const HTTP_MAX_CONCURRENT_STREAMS: u32 = 256;

// The maximum time we should wait for a peeking the first bytes on a TCP
// connection. Effectively, if we can't read the first bytes within the
// timeout the connection is broken.
// If you modify this constant please also adjust:
// - `ic_canister_client::agent::MAX_POLL_INTERVAL`,
// - `canister_test::canister::MAX_BACKOFF_INTERVAL`.
// See VER-1060 for details.
const MAX_TCP_PEEK_TIMEOUT_SECS: u64 = 11;

// Request with body size bigger than 'MAX_REQUEST_SIZE_BYTES' will be rejected
// and appropriate error code will be returned to the user.
pub(crate) const MAX_REQUEST_SIZE_BYTES: usize = 5 * 1024 * 1024; // 5MB

// If the request body is not received/parsed within
// 'MAX_REQUEST_RECEIVE_DURATION', then the request will be rejected and
// appropriate error code will be returned to the user.
pub(crate) const MAX_REQUEST_RECEIVE_DURATION: Duration = Duration::from_secs(300); // 5 min

// Number of times to try fetching the root delegation before giving up.
const MAX_FETCH_DELEGATION_ATTEMPTS: u8 = 10;

const HTTP_DASHBOARD_URL_PATH: &str = "/_/dashboard";
const CONTENT_TYPE_CBOR: &str = "application/cbor";

// Placeholder used when we can't determine the approriate prometheus label.
const UNKNOWN_LABEL: &str = "unknown";

/// The struct that handles incoming HTTP requests for the IC replica.
/// This is collection of thread-safe data members.
#[derive(Clone)]
struct HttpHandler {
    log: ReplicaLogger,
    config: Config,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    subnet_type: SubnetType,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    registry_client: Arc<dyn RegistryClient>,
    validator: Arc<dyn IngressSigVerifier + Send + Sync>,

    // External services  wrapped by tower::Buffer. It is safe to be
    // cloned and passed to a single-threaded context.
    query_execution_service: QueryExecutionService,
    ingress_sender: IngressIngestionService,
    ingress_filter: IngressFilterService,

    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    #[allow(dead_code)]
    backup_spool_path: Option<PathBuf>,
    malicious_flags: MaliciousFlags,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    health_status: Arc<RwLock<ReplicaHealthStatus>>,
}

// Crates a detached tokio blocking task that initializes the server (reading
// required state, etc).
fn start_server_initialization(
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    log: ReplicaLogger,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    health_status: Arc<RwLock<ReplicaHealthStatus>>,
    rt_handle: tokio::runtime::Handle,
) {
    rt_handle.spawn(async move {
        info!(log, "Initializing HTTP server...");
        let mut check_count: i32 = 0;
        // Sleep one second between retries, only log every 10th round.
        info!(log, "Waiting for certified state...");
        *health_status.write().unwrap() = ReplicaHealthStatus::WaitingForCertifiedState;
        while common::get_latest_certified_state(state_reader.as_ref()).is_none() {
            check_count += 1;
            if check_count % 10 == 0 {
                info!(log, "Certified state is not yet available...");
            }
            sleep(Duration::from_secs(1)).await;
        }
        info!(log, "Certified state is now available.");
        // Fetch the delegation from the NNS for this subnet to be
        // able to issue certificates.
        *health_status.write().unwrap() = ReplicaHealthStatus::WaitingForRootDelegation;
        match load_root_delegation(state_reader.as_ref(), subnet_id, nns_subnet_id, &log).await {
            Err(err) => {
                error!(log, "Could not load nns delegation: {}", err);
            }
            Ok(loaded_delegation) => {
                *delegation_from_nns.write().unwrap() = loaded_delegation;
                *health_status.write().unwrap() = ReplicaHealthStatus::Healthy;
                // IMPORTANT: The system-tests relies on this log message to understand when it
                // can start interacting with the replica. In the future, we plan to
                // have a dedicated instrumentation channel to communicate between the
                // replica and the testing framework, but for now, this is the best we can do.
                info!(log, "Ready for interaction.");
            }
        }
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

/// Creates HTTP server, binds to HTTP port and handles HTTP requests forever.
/// This ***async*** function ***never*** returns unless binding to the HTTP
/// port fails.
/// The function spawns a tokio task per connection.
#[allow(clippy::too_many_arguments)]
pub async fn start_server(
    metrics_registry: MetricsRegistry,
    config: Config,
    ingress_filter: IngressFilterService,
    ingress_sender: IngressIngestionService,
    query_execution_service: QueryExecutionService,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    registry_client: Arc<dyn RegistryClient>,
    tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
    ingress_verifier: Arc<dyn IngressSigVerifier + Send + Sync>,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    log: ReplicaLogger,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    backup_spool_path: Option<PathBuf>,
    subnet_type: SubnetType,
    malicious_flags: MaliciousFlags,
    rt_handle: tokio::runtime::Handle,
) -> Result<(), Error> {
    let metrics = HttpHandlerMetrics::new(&metrics_registry);

    let listen_addr = config.listen_addr;
    let port_file_path = config.port_file_path.clone();

    let http_handler = HttpHandler {
        log: log.clone(),
        config,
        subnet_id,
        nns_subnet_id,
        subnet_type,
        state_reader,
        registry_client,
        validator: ingress_verifier,
        query_execution_service,
        ingress_sender,
        ingress_filter,
        consensus_pool_cache,
        backup_spool_path,
        malicious_flags,
        delegation_from_nns: Arc::new(RwLock::new(None)),
        health_status: Arc::new(RwLock::new(ReplicaHealthStatus::Starting)),
    };

    info!(log, "Starting HTTP server...");

    // TODO(OR4-60): temporarily listen on [::] so that we accept both IPv4 and
    // IPv6 connections. This requires net.ipv6.bindv6only = 0. Revert this once
    // we have rolled out IPv6 in prometheus and ic_p8s_service_discovery.
    let mut addr = "[::]:8080".parse::<SocketAddr>().unwrap();
    addr.set_port(listen_addr.port());

    info!(log, "Binding HTTP server to address {}", addr);
    let tcp_listener = TcpListener::bind(addr).await?;

    // If addr == 0, then a random port will be assigned. In this case it
    // is useful to report the randomly assigned port by writing it to a file.
    let local_addr = tcp_listener.local_addr()?;
    if let Some(path) = port_file_path {
        create_port_file(path, local_addr.port());
    }

    start_server_initialization(
        Arc::clone(&http_handler.state_reader),
        http_handler.subnet_id,
        http_handler.nns_subnet_id,
        http_handler.log.clone(),
        Arc::clone(&http_handler.delegation_from_nns),
        Arc::clone(&http_handler.health_status),
        rt_handle.clone(),
    );

    let outstanding_connections =
        ObservableCountingSemaphore::new(MAX_OUTSTANDING_CONNECTIONS, metrics.connections.clone());
    let mut http = Http::new();
    http.http2_max_concurrent_streams(HTTP_MAX_CONCURRENT_STREAMS);
    loop {
        let log = log.clone();
        let http = http.clone();
        let http_handler = http_handler.clone();
        let tls_handshake = Arc::clone(&tls_handshake);
        let metrics = metrics.clone();
        let request_permit = outstanding_connections.acquire().await;
        match tcp_listener.accept().await {
            Ok((tcp_stream, _)) => {
                metrics.connections_total.inc();
                // Start recording connection setup duration.
                let connection_start_time = Instant::now();
                rt_handle.spawn(async move {
                    // Do a move of the permit so it gets dropped at the end of the scope.
                    let _request_permit_deleter = request_permit;
                    let mut b = [0_u8; 1];
                    let serve_https = match timeout(
                        Duration::from_secs(MAX_TCP_PEEK_TIMEOUT_SECS),
                        tcp_stream.peek(&mut b),
                    )
                    .await
                    {
                        // The peek operation didn't timeout, and the peek oparation didn't return
                        // an error.
                        Ok(Ok(_)) => b[0] == 22,
                        Ok(Err(err)) => {
                            warn!(log, "Connection error (can't peek). {}", err);
                            metrics.observe_connection_error(
                                ConnectionError::Peek,
                                connection_start_time,
                            );
                            false
                        }
                        Err(err) => {
                            warn!(
                                log,
                                "Connection error (tcp peeking timeout after {}s). {}",
                                MAX_TCP_PEEK_TIMEOUT_SECS,
                                err
                            );

                            metrics.observe_connection_error(
                                ConnectionError::PeekTimeout,
                                connection_start_time,
                            );
                            false
                        }
                    };
                    if serve_https {
                        serve_secure_connection(
                            tls_handshake,
                            tcp_stream,
                            metrics,
                            http,
                            http_handler,
                            connection_start_time,
                            log,
                        )
                        .await;
                    } else {
                        // If either
                        //      1. peeking timed out
                        //      2. peeking failed
                        //      3. first byte is not 22
                        // then fallback to HTTP.
                        serve_unsecure_connection(
                            metrics,
                            http,
                            http_handler,
                            tcp_stream,
                            connection_start_time,
                            log,
                        )
                        .await;
                    }
                });
            }
            // Don't exit the loop on a connection error. We will want to
            // continue serving.
            Err(err) => {
                metrics.observe_connection_error(ConnectionError::Accept, Instant::now());
                warn!(log, "Connection error (can't accept) {}", err);
            }
        }
    }
}

fn create_main_service(
    metrics: HttpHandlerMetrics,
    http_handler: HttpHandler,
    app_layer: AppLayer,
) -> BoxService<Request<Body>, Response<Body>, CanonicalError> {
    let metrics_for_map_request = metrics.clone();
    let route_service = service_fn(move |req: RequestWithTimer| {
        let metrics = metrics.clone();
        let http_handler = http_handler.clone();
        async move { Ok::<_, BoxError>(make_router(metrics, http_handler, app_layer, req).await) }
    });
    BoxService::new(
        ServiceBuilder::new()
            // Attach a timer as soon as we see a request.
            .map_request(move |request| {
                // Start recording request duration.
                let request_timer = HistogramVecTimer::start_timer(
                    metrics_for_map_request.requests.clone(),
                    &REQUESTS_LABEL_NAMES,
                    [UNKNOWN_LABEL, UNKNOWN_LABEL, UNKNOWN_LABEL],
                );
                (request, request_timer)
            })
            .service(route_service)
            .map_result(move |result| match result {
                Ok((response, request_timer)) => {
                    let status = response.status();
                    // This is a workaround for `StatusCode::as_str()` not returning a `&'static
                    // str`. It ensures `request_timer` is dropped before `status`.
                    let mut timer = request_timer;
                    timer.set_label(LABEL_STATUS, status.as_str());
                    Ok::<_, CanonicalError>(response)
                }
                Err(_err) => Err(unknown_error(
                    "We should never return an error here.".to_string(),
                )),
            }),
    )
}

async fn serve_unsecure_connection(
    metrics: HttpHandlerMetrics,
    http: Http,
    http_handler: HttpHandler,
    tcp_stream: TcpStream,
    connection_start_time: Instant,
    log: ReplicaLogger,
) {
    let service = create_main_service(metrics.clone(), http_handler, AppLayer::Http);
    if let Err(err) = http.serve_connection(tcp_stream, service).await {
        metrics.observe_connection_error(
            ConnectionError::ServingHttpConnection,
            connection_start_time,
        );
        warn!(
            log,
            "Connection error (can't serve HTTP connection): {}", err
        );
    } else {
        metrics.observe_connection_setup(AppLayer::Http, connection_start_time)
    }
}

async fn serve_secure_connection(
    tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
    tcp_stream: TcpStream,
    metrics: HttpHandlerMetrics,
    http: Http,
    http_handler: HttpHandler,
    connection_start_time: Instant,
    log: ReplicaLogger,
) {
    let registry_version = http_handler.registry_client.get_latest_version();
    let service = create_main_service(metrics.clone(), http_handler, AppLayer::Https);
    match tls_handshake
        .perform_tls_server_handshake_without_client_auth(tcp_stream, registry_version)
        .await
    {
        Err(err) => {
            metrics.observe_connection_error(ConnectionError::TlsHandshake, connection_start_time);
            warn!(log, "Connection error (TLS handshake): {}", err);
        }
        Ok(tls_stream) => {
            if let Err(err) = http.serve_connection(tls_stream, service).await {
                metrics.observe_connection_error(
                    ConnectionError::ServingHttpsConnection,
                    connection_start_time,
                );
                warn!(
                    log,
                    "Connection error (can't serve HTTPS connection): {}", err
                );
            } else {
                metrics.observe_connection_setup(AppLayer::Https, connection_start_time)
            }
        }
    }
}

type RequestWithTimer = (
    Request<Body>,
    HistogramVecTimer<'static, REQUESTS_NUM_LABELS>,
);
type ResponseWithTimer = (
    Response<Body>,
    HistogramVecTimer<'static, REQUESTS_NUM_LABELS>,
);

fn set_timer_labels(
    timer: &mut HistogramVecTimer<'static, REQUESTS_NUM_LABELS>,
    req_type: RequestType,
    api_req_type: ApiReqType,
) {
    timer.set_label(LABEL_TYPE, req_type.as_str());
    timer.set_label(LABEL_REQUEST_TYPE, api_req_type.as_str());
}

async fn make_router(
    metrics: HttpHandlerMetrics,
    http_handler: HttpHandler,
    app_layer: AppLayer,
    (req, mut timer): RequestWithTimer,
) -> ResponseWithTimer {
    use http::method::Method;

    let query_service = BoxService::new(
        ServiceBuilder::new()
            .layer(BodyReceiverLayer::default())
            .service(QueryService::new(
                http_handler.log.clone(),
                metrics.clone(),
                Arc::clone(&http_handler.health_status),
                Arc::clone(&http_handler.delegation_from_nns),
                Arc::clone(&http_handler.validator),
                Arc::clone(&http_handler.registry_client),
                http_handler.query_execution_service.clone(),
                http_handler.malicious_flags.clone(),
            )),
    );
    let status_service = BoxService::new(StatusService::new(
        http_handler.log.clone(),
        http_handler.config.clone(),
        http_handler.nns_subnet_id,
        Arc::clone(&http_handler.state_reader),
        Arc::clone(&http_handler.health_status),
    ));
    let dashboard_service = BoxService::new(DashboardService::new(
        http_handler.config,
        http_handler.subnet_type,
        Arc::clone(&http_handler.state_reader),
    ));
    let catch_up_package_service = BoxService::new(
        ServiceBuilder::new()
            .layer(BodyReceiverLayer::default())
            .service(CatchUpPackageService::new(
                metrics.clone(),
                http_handler.consensus_pool_cache,
            )),
    );
    let read_state_service = BoxService::new(
        ServiceBuilder::new()
            .layer(BodyReceiverLayer::default())
            .service(ReadStateService::new(
                http_handler.log.clone(),
                metrics.clone(),
                Arc::clone(&http_handler.health_status),
                Arc::clone(&http_handler.delegation_from_nns),
                Arc::clone(&http_handler.state_reader),
                Arc::clone(&http_handler.validator),
                Arc::clone(&http_handler.registry_client),
                http_handler.malicious_flags.clone(),
            )),
    );
    let call_service = BoxService::new(
        ServiceBuilder::new()
            .layer(BodyReceiverLayer::default())
            .service(CallService::new(
                http_handler.log.clone(),
                metrics.clone(),
                http_handler.subnet_id,
                Arc::clone(&http_handler.registry_client),
                Arc::clone(&http_handler.validator),
                http_handler.ingress_sender,
                http_handler.ingress_filter,
                http_handler.malicious_flags.clone(),
            )),
    );

    let invalid_argument_response = common::make_response(invalid_argument_error(String::new()));
    metrics
        .protocol_version_total
        .with_label_values(&[app_layer.as_str(), &format!("{:?}", req.version())])
        .inc();
    let svc = match *req.method() {
        Method::POST => {
            // Check the content-type header
            if !req
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
                set_timer_labels(
                    &mut timer,
                    RequestType::InvalidArgument,
                    ApiReqType::InvalidArgument,
                );
                return (invalid_argument_response, timer);
            }

            // Check the path
            let path = req.uri().path();
            match *path.split('/').collect::<Vec<&str>>().as_slice() {
                ["", "api", "v2", "canister", _, "call"] => {
                    set_timer_labels(&mut timer, RequestType::Submit, ApiReqType::Call);
                    call_service
                }
                ["", "api", "v2", "canister", _, "query"] => {
                    set_timer_labels(&mut timer, RequestType::Query, ApiReqType::Query);
                    query_service
                }
                ["", "api", "v2", "canister", _, "read_state"] => {
                    set_timer_labels(&mut timer, RequestType::ReadState, ApiReqType::ReadState);
                    read_state_service
                }
                ["", "_", "catch_up_package"] => {
                    set_timer_labels(
                        &mut timer,
                        RequestType::CatchUpPackage,
                        ApiReqType::CatchUpPackage,
                    );
                    catch_up_package_service
                }
                _ => {
                    set_timer_labels(
                        &mut timer,
                        RequestType::InvalidArgument,
                        ApiReqType::InvalidArgument,
                    );
                    return (invalid_argument_response, timer);
                }
            }
        }
        Method::GET => match req.uri().path() {
            "/api/v2/status" => {
                set_timer_labels(&mut timer, RequestType::Status, ApiReqType::Status);
                status_service
            }
            "/" | "/_/" => {
                set_timer_labels(
                    &mut timer,
                    RequestType::RedirectToDashboard,
                    ApiReqType::RedirectToDashboard,
                );
                return (redirect_to_dasboard_response(), timer);
            }
            HTTP_DASHBOARD_URL_PATH => {
                set_timer_labels(&mut timer, RequestType::Dashboard, ApiReqType::Dashboard);
                dashboard_service
            }
            "/_/pprof" => {
                set_timer_labels(&mut timer, RequestType::PprofHome, ApiReqType::PprofHome);
                return (pprof::home(), timer);
            }
            "/_/pprof/profile" => {
                set_timer_labels(
                    &mut timer,
                    RequestType::PprofProfile,
                    ApiReqType::PprofProfile,
                );
                return (pprof::cpu_profile(req.into_parts().0).await, timer);
            }
            "/_/pprof/flamegraph" => {
                set_timer_labels(
                    &mut timer,
                    RequestType::PprofFlamegraph,
                    ApiReqType::PprofFlamegraph,
                );
                return (pprof::cpu_flamegraph(req.into_parts().0).await, timer);
            }
            _ => {
                set_timer_labels(
                    &mut timer,
                    RequestType::InvalidArgument,
                    ApiReqType::InvalidArgument,
                );
                return (invalid_argument_response, timer);
            }
        },
        Method::OPTIONS => {
            set_timer_labels(&mut timer, RequestType::Options, ApiReqType::Options);
            return (no_content_response(), timer);
        }
        _ => {
            set_timer_labels(
                &mut timer,
                RequestType::InvalidArgument,
                ApiReqType::InvalidArgument,
            );
            return (invalid_argument_response, timer);
        }
    };
    (
        LoadShed::new(svc)
            .ready()
            .await
            .expect("The load shedder must always be ready.")
            .call(req.into_body())
            .await
            .unwrap_or_else(|err| map_box_error_to_response(err)),
        timer,
    )
}

// Fetches a delegation from the NNS subnet to allow this subnet to issue
// certificates on its behalf. On the NNS subnet this method is a no-op.
async fn load_root_delegation(
    state_reader: &dyn StateReader<State = ReplicatedState>,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    log: &ReplicaLogger,
) -> Result<Option<CertificateDelegation>, Error> {
    if subnet_id == nns_subnet_id {
        info!(log, "On the NNS subnet. Skipping fetching the delegation.");
        // On the NNS subnet. No delegation needs to be fetched.
        return Ok(None);
    }

    for _ in 0..MAX_FETCH_DELEGATION_ATTEMPTS {
        info!(log, "Fetching delegation from the nns subnet...");

        async fn log_err_and_backoff(log: &ReplicaLogger, err: impl std::fmt::Display) {
            // Fetching the NNS delegation failed. Do a random backoff and try again.
            let backoff = Duration::from_secs(rand::thread_rng().gen_range(1..15));
            warn!(
                log,
                "Fetching delegation from nns subnet failed. Retrying again in {} seconds...\n\
                    Error received: {}",
                backoff.as_secs(),
                err
            );
            sleep(backoff).await
        }

        let node = match get_random_node_from_nns_subnet(state_reader, nns_subnet_id) {
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
                    ingress_expiry: current_time_and_expiry_time().1.as_nanos_since_unix_epoch(),
                    nonce: None,
                },
            },
            sender_pubkey: None,
            sender_sig: None,
            sender_delegation: None,
        };

        let body = serde_cbor::ser::to_vec(&envelope).unwrap();
        let http_client = reqwest::blocking::Client::new();
        let ip_addr = node.ip_address.parse().unwrap();
        // any effective canister id can be used when invoking read_state here
        let address = format!(
            "http://{}/api/v2/canister/aaaaa-aa/read_state",
            SocketAddr::new(ip_addr, node.http_port)
        );
        info!(
            log,
            "Attempt to fetch delegation from root subnet node with url `{}`", address
        );
        let raw_response_res = match http_client
            .post(&address)
            .header(hyper::header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .body(body)
            .send()
        {
            Ok(res) => res.bytes(),
            Err(err) => {
                log_err_and_backoff(log, &err).await;
                continue;
            }
        };

        match raw_response_res {
            Ok(raw_response) => {
                debug!(log, "Response from nns subnet: {:?}", raw_response);

                let response: HttpReadStateResponse = match serde_cbor::from_slice(&raw_response) {
                    Ok(r) => r,
                    Err(e) => {
                        log_err_and_backoff(log, &e).await;
                        continue;
                    }
                };

                let parsed_delegation: Certificate =
                    match serde_cbor::from_slice(&response.certificate) {
                        Ok(r) => r,
                        Err(e) => {
                            log_err_and_backoff(
                                log,
                                &format!("failed to parse delegation certificate: {}", e),
                            )
                            .await;
                            continue;
                        }
                    };

                let labeled_tree = match LabeledTree::try_from(parsed_delegation.tree) {
                    Ok(r) => r,
                    Err(e) => {
                        log_err_and_backoff(
                            log,
                            &format!("invalid hash tree in the delegation certificate: {:?}", e),
                        )
                        .await;
                        continue;
                    }
                };

                if lookup_path(
                    &labeled_tree,
                    &[b"subnet", subnet_id.get_ref().as_ref(), b"public_key"],
                )
                .is_none()
                {
                    log_err_and_backoff(
                        log,
                        &format!("delegation does not contain current subnet {}", subnet_id),
                    )
                    .await;
                    continue;
                }

                let delegation = CertificateDelegation {
                    subnet_id: Blob(subnet_id.get().to_vec()),
                    certificate: response.certificate,
                };

                info!(log, "Setting NNS delegation to: {:?}", delegation);
                return Ok(Some(delegation));
            }
            Err(err) => {
                // Fetching the NNS delegation failed. Do a random backoff and try again.
                log_err_and_backoff(log, &err).await;
            }
        }
    }
    Err(Error::new(
        ErrorKind::TimedOut,
        format!(
            "Couldn't load NNS delegation after {} attempts.",
            MAX_FETCH_DELEGATION_ATTEMPTS
        ),
    ))
}

fn get_random_node_from_nns_subnet(
    state_reader: &dyn StateReader<State = ReplicatedState>,
    nns_subnet_id: SubnetId,
) -> Result<NodeTopology, String> {
    use rand::seq::IteratorRandom;

    let subnet_topologies = &state_reader
        .get_latest_state()
        .take()
        .metadata
        .network_topology
        .subnets;

    let nns_subnet_topology = subnet_topologies.get(&nns_subnet_id).ok_or_else(|| {
        String::from("NNS subnet not found in network topology. Skipping fetching the delegation.")
    })?;

    // Randomly choose a node from the nns subnet.
    let mut rng = rand::thread_rng();
    nns_subnet_topology
        .nodes
        .values()
        .choose(&mut rng)
        .cloned()
        .ok_or_else(|| {
            String::from("NNS subnet contains no nodes. Skipping fetching the delegation.")
        })
}

fn no_content_response() -> Response<Body> {
    let mut response = Response::new(Body::from(""));
    *response.status_mut() = StatusCode::NO_CONTENT;
    *response.headers_mut() = get_cors_headers();
    response
}

fn redirect_to_dasboard_response() -> Response<Body> {
    // The empty string is simply to uniformize the return type with the cases where
    // the response is not empty.
    let mut response = Response::new(Body::from(""));
    *response.status_mut() = StatusCode::FOUND;
    response.headers_mut().insert(
        hyper::header::LOCATION,
        hyper::header::HeaderValue::from_static(HTTP_DASHBOARD_URL_PATH),
    );
    response
}
