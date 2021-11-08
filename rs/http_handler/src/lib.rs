/// This is the entry point of the Internet Computer. This deals with
/// accepting HTTP connections, parsing messages and forwarding them to the
/// correct components.
///
/// As much as possible the naming of structs in this module should match the
/// naming used in the [Interface
/// Specification](https://sdk.dfinity.org/docs/interface-spec/index.html)
mod catch_up_package;
mod common;
mod dashboard;
mod metrics;
mod pprof;
mod query;
mod read_state;
mod status;
mod submit;
mod types;

use crate::{
    catch_up_package::CatchUpPackageService,
    dashboard::DashboardService,
    metrics::{
        LABEL_REQUEST_TYPE, LABEL_STATUS, LABEL_TYPE, REQUESTS_LABEL_NAMES, REQUESTS_NUM_LABELS,
    },
    read_state::ReadStateService,
    status::StatusService,
    types::*,
};
use futures_util::stream::StreamExt;
use http::request::Parts;
use hyper::{server::conn::Http, Body, Request, Response, StatusCode};
use ic_base_thread::ObservableCountingSemaphore;
use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_crypto_tree_hash::Path;
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
    canonical_error::{
        internal_error, invalid_argument_error, out_of_range_error, resource_exhausted_error,
        unknown_error, CanonicalError,
    },
    malicious_flags::MaliciousFlags,
    messages::{
        Blob, CertificateDelegation, HttpReadContent, HttpReadState, HttpReadStateResponse,
        HttpRequestEnvelope, ReplicaHealthStatus,
    },
    time::current_time_and_expiry_time,
    SubnetId,
};
use metrics::HttpHandlerMetrics;
use rand::Rng;
use std::io::{Error, ErrorKind, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time::{timeout, Instant},
};
use tower::{
    limit::ConcurrencyLimit,
    load_shed::{error::Overloaded, LoadShed},
    service_fn, BoxError, Service, ServiceBuilder, ServiceExt,
};
use tower_util::BoxService;

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
const MAX_OUTSTANDING_CONNECTIONS: usize = 30000;

/// The max requests per second per connection.
const MAX_REQUESTS_PER_SECOND_PER_CONNECTION: u64 = 500;

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
const MAX_REQUEST_SIZE_BYTES: usize = 5 * 1024 * 1024; // 5MB

// If the request body is not received/parsed within
// 'MAX_REQUEST_RECEIVE_DURATION', then the request will be rejected and
// appropriate error code will be returned to the user.
const MAX_REQUEST_RECEIVE_DURATION: Duration = Duration::from_secs(300); // 5 min

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
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    registry_client: Arc<dyn RegistryClient>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    validator: Arc<dyn IngressSigVerifier + Send + Sync>,

    ingress_filter: Arc<Mutex<IngressFilterService>>,
    ingress_sender: Arc<Mutex<IngressIngestionService>>,
    query_handler: Arc<Mutex<QueryExecutionService>>,
    read_state_service: LoadShed<ConcurrencyLimit<ReadStateService>>,
    status_service: LoadShed<ConcurrencyLimit<StatusService>>,
    dashboard_service: LoadShed<ConcurrencyLimit<DashboardService>>,
    catch_up_package_service: LoadShed<ConcurrencyLimit<CatchUpPackageService>>,
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
) {
    tokio::task::spawn_blocking(move || {
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
            std::thread::sleep(Duration::from_secs(1));
        }
        info!(log, "Certified state is now available.");
        // Fetch the delegation from the NNS for this subnet to be
        // able to issue certificates.
        *health_status.write().unwrap() = ReplicaHealthStatus::WaitingForRootDelegation;
        match load_root_delegation(state_reader.as_ref(), subnet_id, nns_subnet_id, &log) {
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

fn make_response(status_code: StatusCode, body: &str) -> Response<Body> {
    let mut resp = Response::new(Body::from(body.to_string()));
    *resp.status_mut() = status_code;
    *resp.headers_mut() = common::get_cors_headers();
    resp
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
    query_handler: QueryExecutionService,
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
) -> Result<(), Error> {
    let metrics = Arc::new(HttpHandlerMetrics::new(&metrics_registry));

    let listen_addr = config.listen_addr;
    let port_file_path = config.port_file_path.clone();

    let http_handler = HttpHandler::new(
        config,
        registry_client,
        subnet_id,
        subnet_type,
        nns_subnet_id,
        log.clone(),
        Arc::new(Mutex::new(ingress_filter)),
        Arc::new(Mutex::new(ingress_sender)),
        Arc::new(Mutex::new(query_handler)),
        state_reader,
        ingress_verifier,
        consensus_pool_cache,
        backup_spool_path,
        malicious_flags,
    );

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
    );

    let outstanding_connections =
        ObservableCountingSemaphore::new(MAX_OUTSTANDING_CONNECTIONS, metrics.connections.clone());

    loop {
        let log = log.clone();
        let http_handler = http_handler.clone();
        let tls_handshake = Arc::clone(&tls_handshake);
        let metrics = Arc::clone(&metrics);
        let request_permit = outstanding_connections.acquire().await;
        match tcp_listener.accept().await {
            Ok((tcp_stream, _)) => {
                metrics.connections_total.inc();
                // Start recording connection setup duration.
                let connection_start_time = Instant::now();
                tokio::task::spawn(async move {
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

impl HttpHandler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: Config,
        registry_client: Arc<dyn RegistryClient>,
        subnet_id: SubnetId,
        subnet_type: SubnetType,
        nns_subnet_id: SubnetId,
        log: ReplicaLogger,
        ingress_filter: Arc<Mutex<IngressFilterService>>,
        ingress_sender: Arc<Mutex<IngressIngestionService>>,
        query_handler: Arc<Mutex<QueryExecutionService>>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        validator: Arc<dyn IngressSigVerifier + Send + Sync>,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        backup_spool_path: Option<PathBuf>,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        let health_status = Arc::new(RwLock::new(ReplicaHealthStatus::Starting));
        let delegation_from_nns = Arc::new(RwLock::new(None));
        let status_service = StatusService::new(
            log.clone(),
            config.clone(),
            nns_subnet_id,
            Arc::clone(&state_reader),
            Arc::clone(&health_status),
        );
        let dashboard_service =
            DashboardService::new(config, subnet_type, Arc::clone(&state_reader));
        let catch_up_package_service = CatchUpPackageService::new(consensus_pool_cache);
        let read_state_service = ReadStateService::new(
            log.clone(),
            Arc::clone(&health_status),
            Arc::clone(&delegation_from_nns),
            Arc::clone(&state_reader),
            Arc::clone(&validator),
            Arc::clone(&registry_client),
            malicious_flags.clone(),
        );
        Self {
            log,
            subnet_id,
            nns_subnet_id,
            registry_client,
            state_reader,
            validator,
            ingress_filter,
            ingress_sender,
            query_handler,
            read_state_service,
            status_service,
            dashboard_service,
            catch_up_package_service,
            backup_spool_path,
            malicious_flags,
            delegation_from_nns,
            health_status,
        }
    }
}

fn create_main_service(
    metrics: Arc<HttpHandlerMetrics>,
    http_handler: HttpHandler,
    app_layer: AppLayer,
) -> BoxService<Request<Body>, Response<Body>, CanonicalError> {
    let metrics_for_map_request = Arc::clone(&metrics);
    let metrics_for_map_result = Arc::clone(&metrics);
    let route_service = service_fn(move |(request, timer)| {
        let route_metrics = Arc::clone(&metrics);
        let route_http_handler = http_handler.clone();
        async move {
            Ok::<_, BoxError>(
                route(route_metrics, route_http_handler, app_layer, request, timer).await,
            )
        }
    });
    BoxService::new(
        ServiceBuilder::new()
            .load_shed()
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
            // The RegistryClient and the StateManager are shared between requests. Both structures
            // are not lock-free and their avg. API latency is less than 1 millisecond. Since we
            // need to serialize the access, we should not send more than 500 requests per second.
            // Please note that the downstream services (query execution and ingress ingestion) have
            // buffers which are used for load shedding. So in case of very high latency in the
            // downstream services, they will do their own load shedding.
            // IMPORTANT: the service is per connection, if we have many connections sending huge
            // load of traffic to the replica we will still have some risk of overloading it due to
            // contention. For the time being the boundary nodes have just a single connection
            // opened to a replica on which they multiplex requests.
            .rate_limit(
                MAX_REQUESTS_PER_SECOND_PER_CONNECTION,
                Duration::from_secs(1),
            )
            .service(route_service)
            .map_result(move |result| match result {
                Ok(response) => Ok(response),
                Err(err) => {
                    // We may get an error only when the load shedding kicks in.
                    let mut response = make_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Service unavailable. Too many buffered requests",
                    );
                    let request_timer = HistogramVecTimer::start_timer(
                        metrics_for_map_result.requests.clone(),
                        &REQUESTS_LABEL_NAMES,
                        [UNKNOWN_LABEL, UNKNOWN_LABEL, UNKNOWN_LABEL],
                    );
                    if !err.is::<Overloaded>() {
                        response = make_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Unexpected internal error.",
                        );
                    }
                    let status = response.status();
                    // This is a workaround for `StatusCode::as_str()` not returning a `&'static
                    // str`. It ensures `request_timer` is dropped before `status`.
                    let mut request_timer = request_timer;
                    request_timer.set_label(LABEL_STATUS, status.as_str());
                    Ok(response)
                }
            }),
    )
}

async fn serve_unsecure_connection(
    metrics: Arc<HttpHandlerMetrics>,
    http_handler: HttpHandler,
    tcp_stream: TcpStream,
    connection_start_time: Instant,
    log: ReplicaLogger,
) {
    let http = Http::new();
    let service = create_main_service(Arc::clone(&metrics), http_handler, AppLayer::Http);
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
    metrics: Arc<HttpHandlerMetrics>,
    http_handler: HttpHandler,
    connection_start_time: Instant,
    log: ReplicaLogger,
) {
    let registry_version = http_handler.registry_client.get_latest_version();
    let http = Http::new();
    let service = create_main_service(Arc::clone(&metrics), http_handler, AppLayer::Https);
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

async fn route(
    metrics: Arc<HttpHandlerMetrics>,
    http_handler: HttpHandler,
    app_layer: AppLayer,
    request: Request<Body>,
    mut request_timer: HistogramVecTimer<'_, REQUESTS_NUM_LABELS>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();
    metrics
        .protocol_version_total
        .with_label_values(&[app_layer.as_str(), &format!("{:?}", parts.version)])
        .inc();
    let result = match validate_http_request_head(&parts) {
        Ok(request_type) => {
            request_timer.set_label(LABEL_TYPE, request_type.as_str());
            let parse_body_result = match request_type {
                RequestType::Options | RequestType::RedirectToDashboard => Ok(Vec::new()),
                _ => parse_body(body, MAX_REQUEST_RECEIVE_DURATION, MAX_REQUEST_SIZE_BYTES).await,
            };
            match parse_body_result {
                Ok(parsed_body) => {
                    let body_size = parsed_body.len();
                    let (response, api_req_type) =
                        route_to_handlers(http_handler, parsed_body, request_type, parts).await;

                    let status = response.status();
                    // This is a workaround for `StatusCode::as_str()` not returning a `&'static
                    // str`. It ensures `request_timer` is dropped before `status`.
                    let mut request_timer = request_timer;
                    request_timer.set_label(LABEL_REQUEST_TYPE, api_req_type.as_str());
                    request_timer.set_label(LABEL_STATUS, status.as_str());
                    metrics
                        .requests_body_size_bytes
                        .with_label_values(request_timer.label_values())
                        .observe(body_size as f64);

                    Ok(response)
                }
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    };
    result.unwrap_or_else(|canonical_error| {
        make_response(
            StatusCode::from(canonical_error.code),
            canonical_error.message.as_str(),
        )
    })
}

fn map_box_error_to_canonical_error(err: BoxError) -> CanonicalError {
    if err.is::<CanonicalError>() {
        return *err
            .downcast::<CanonicalError>()
            .expect("Downcasting must succeed.");
    }
    if err.is::<Overloaded>() {
        return resource_exhausted_error("The service is overloaded.");
    }
    internal_error(&format!("Could not convert {:?} to CanonicalError", err))
}

async fn route_to_handlers(
    mut http_handler: HttpHandler,
    parsed_body: Vec<u8>,
    request_type: RequestType,
    parts: Parts,
) -> (Response<Body>, ApiReqType) {
    let (result, api_req_type) = match request_type {
        RequestType::Query => (
            query::handle(
                &http_handler.log,
                Arc::clone(&http_handler.health_status),
                Arc::clone(&http_handler.delegation_from_nns),
                Arc::clone(&http_handler.query_handler),
                Arc::clone(&http_handler.validator),
                Arc::clone(&http_handler.registry_client),
                parsed_body,
                http_handler.malicious_flags.clone(),
            )
            .await,
            ApiReqType::Query,
        ),
        RequestType::ReadState => (
            http_handler
                .read_state_service
                .ready()
                .await
                .expect("The service must always be able to process requests")
                .call(parsed_body)
                .await
                .map_err(|err| map_box_error_to_canonical_error(err)),
            ApiReqType::ReadState,
        ),
        RequestType::Submit => (
            submit::handle(
                http_handler.log.clone(),
                http_handler.subnet_id,
                Arc::clone(&http_handler.registry_client),
                Arc::clone(&http_handler.validator),
                Arc::clone(&http_handler.ingress_sender),
                Arc::clone(&http_handler.ingress_filter),
                http_handler.malicious_flags.clone(),
                parsed_body,
            )
            .await,
            ApiReqType::Call,
        ),
        RequestType::Status => (
            http_handler
                .status_service
                .ready()
                .await
                .expect("The service must always be able to process requests")
                .call(())
                .await
                .map_err(|err| map_box_error_to_canonical_error(err)),
            ApiReqType::Unknown,
        ),
        RequestType::Dashboard => (
            http_handler
                .dashboard_service
                .ready()
                .await
                .expect("The service must always be able to process requests")
                .call(())
                .await
                .map_err(|err| map_box_error_to_canonical_error(err)),
            ApiReqType::Unknown,
        ),
        RequestType::CatchUpPackage => (
            http_handler
                .catch_up_package_service
                .ready()
                .await
                .expect("The service must always be able to process requests")
                .call(parsed_body)
                .await
                .map_err(|err| map_box_error_to_canonical_error(err)),
            ApiReqType::Unknown,
        ),
        RequestType::RedirectToDashboard => (Ok(redirect_to_dashboard()), ApiReqType::Unknown),
        RequestType::Options => (
            Ok(make_response(StatusCode::NO_CONTENT, "")),
            ApiReqType::Unknown,
        ),
        RequestType::Pprof(page) => (pprof::handle(page, parts).await, ApiReqType::Unknown),
    };
    (
        result.unwrap_or_else(|err| make_response(StatusCode::from(err.code), &err.message)),
        api_req_type,
    )
}

// Fetches a delegation from the NNS subnet to allow this subnet to issue
// certificates on its behalf. On the NNS subnet this method is a no-op.
fn load_root_delegation(
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

        let log_err_and_backoff = |err: &dyn std::error::Error| {
            // Fetching the NNS delegation failed. Do a random backoff and try again.
            let mut rng = rand::thread_rng();
            let backoff = Duration::from_secs(rng.gen_range(1..15));
            warn!(
                log,
                "Fetching delegation from nns subnet failed. Retrying again in {} seconds...\n\
                    Error received: {}",
                backoff.as_secs(),
                err
            );
            std::thread::sleep(backoff);
        };

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
            content: HttpReadContent::ReadState {
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
                log_err_and_backoff(&err);
                continue;
            }
        };

        match raw_response_res {
            Ok(raw_response) => {
                debug!(log, "Response from nns subnet: {:?}", raw_response);

                let response: HttpReadStateResponse = match serde_cbor::from_slice(&raw_response) {
                    Ok(r) => r,
                    Err(e) => {
                        log_err_and_backoff(&e);
                        continue;
                    }
                };

                let delegation = CertificateDelegation {
                    subnet_id: Blob(subnet_id.get().to_vec()),
                    certificate: response.certificate,
                };

                info!(log, "Setting NNS delegation to: {:?}", delegation);
                return Ok(Some(delegation));
            }
            Err(err) => {
                // Fetching the NNS delegation failed. Do a random backoff and try again.
                log_err_and_backoff(&err);
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

async fn parse_body(
    mut body: Body,
    max_request_receive_duration: Duration,
    max_request_body_size_bytes: usize,
) -> Result<Vec<u8>, CanonicalError> {
    // Read "content-length" bytes
    // Parse the body only when needed.
    let mut parsed_body = Vec::<u8>::new();
    // Timeout when we are waiting for the next chunk because this wait depends on
    // the user.
    loop {
        match timeout(max_request_receive_duration, body.next()).await {
            Ok(chunk_option) => match chunk_option {
                Some(chunk) => match chunk {
                    Err(err) => {
                        return Err(unknown_error(
                            format!("Unexpected error while reading request: {}", err).as_str(),
                        ));
                    }
                    Ok(bytes) => {
                        if parsed_body.len() + bytes.len() > max_request_body_size_bytes {
                            return Err(out_of_range_error(
                                format!(
                                    "The request body is bigger than {} bytes.",
                                    max_request_body_size_bytes
                                )
                                .as_str(),
                            ));
                        }
                        parsed_body.append(&mut bytes.to_vec());
                    }
                },
                // End of stream.
                None => {
                    return Ok(parsed_body);
                }
            },
            Err(_err) => {
                return Err(out_of_range_error(&format!(
                    "The request body was not received within {:?} seconds.",
                    max_request_receive_duration
                )));
            }
        }
    }
}

// Here we perform a few checks:
//  * Is the method correct, e.g. POST?
//  * Is there a "content-type: application/cbor" header?
//  * Is the path correct?
//  In case validatation fails we return a response as part of Err().
fn validate_http_request_head(parts: &http::request::Parts) -> Result<RequestType, CanonicalError> {
    use http::method::Method;
    match parts.method {
        Method::POST => {
            // Check the content-type header
            if !parts
                .headers
                .get_all(http::header::CONTENT_TYPE)
                .iter()
                .any(|value| {
                    if let Ok(v) = value.to_str() {
                        return v.to_lowercase() == CONTENT_TYPE_CBOR;
                    }
                    false
                })
            {
                return Err(invalid_argument_error(&format!(
                    "Expecting {} cotent-type",
                    CONTENT_TYPE_CBOR
                )));
            }

            // Check the path
            let path = parts.uri.path();
            match *path.split('/').collect::<Vec<&str>>().as_slice() {
                ["", "api", "v2", "canister", _, "call"] => Ok(RequestType::Submit),
                ["", "api", "v2", "canister", _, "query"] => Ok(RequestType::Query),
                ["", "api", "v2", "canister", _, "read_state"] => Ok(RequestType::ReadState),
                ["", "_", "catch_up_package"] => Ok(RequestType::CatchUpPackage),
                _ => Err(invalid_argument_error("URI path is not supported.")),
            }
        }
        Method::GET => match parts.uri.path() {
            "/api/v2/status" => Ok(RequestType::Status),

            "/" | "/_/" => Ok(RequestType::RedirectToDashboard),
            HTTP_DASHBOARD_URL_PATH => Ok(RequestType::Dashboard),

            "/_/pprof" => Ok(RequestType::Pprof(PprofPage::Home)),
            "/_/pprof/profile" => Ok(RequestType::Pprof(PprofPage::Profile)),
            "/_/pprof/flamegraph" => Ok(RequestType::Pprof(PprofPage::Flamegraph)),
            _ => Err(invalid_argument_error("Unsupported method")),
        },
        Method::OPTIONS => Ok(RequestType::Options),
        _ => Err(invalid_argument_error("Unsupported method")),
    }
}

fn redirect_to_dashboard() -> Response<Body> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    #[tokio::test]
    async fn test_succesfully_parse_small_body() {
        let (mut sender, body) = Body::channel();
        assert!(sender
            .send_data(bytes::Bytes::from("hello world"))
            .await
            .is_ok());
        // We need to drop the channel so 'parse_body' will know there aren't any new
        // chunks. If we remove this line the test should run forever.
        std::mem::drop(sender);
        assert_eq!(
            parse_body(body, MAX_REQUEST_RECEIVE_DURATION, MAX_REQUEST_SIZE_BYTES)
                .await
                .ok(),
            Some(Vec::<u8>::from("hello world"))
        );
    }

    #[tokio::test]
    async fn test_stop_and_return_error_when_parsing_big_body() {
        let (mut sender, body) = Body::channel();
        let chunk_size: usize = 1024;
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(chunk_size)
            .map(char::from)
            .collect();

        let jh = tokio::task::spawn(parse_body(
            body,
            MAX_REQUEST_RECEIVE_DURATION,
            MAX_REQUEST_SIZE_BYTES,
        ));
        for _i in 0..(MAX_REQUEST_SIZE_BYTES / chunk_size) {
            assert!(sender
                .send_data(bytes::Bytes::from(rand_string.clone()))
                .await
                .is_ok());
        }
        // We are at the limit, so sending an extra byte will succeed and cause the
        // parse_body function to return.
        assert!(sender.send_data(bytes::Bytes::from("a")).await.is_ok());
        let response = jh
            .await
            .unwrap()
            .expect_err("parse_body must have returned an Err.");
        assert_eq!(
            response,
            out_of_range_error(&format!(
                "The request body is bigger than {} bytes.",
                MAX_REQUEST_SIZE_BYTES
            ))
        );
        // Check we can't send more data. The other end of the channel - the body - is
        // dropped.
        assert!(sender
            .send_data(bytes::Bytes::from(rand_string.clone()))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_time_out_during_body_parsing() {
        let (mut sender, body) = Body::channel();
        let time_to_wait = Duration::from_secs(5);
        let jh = tokio::task::spawn(parse_body(body, time_to_wait, MAX_REQUEST_SIZE_BYTES));
        assert!(sender
            .send_data(bytes::Bytes::from("hello world"))
            .await
            .is_ok());
        // If we drop the sender here the test will fail because parse_body has all the
        // chunks so it won't timeout.
        tokio::time::sleep(time_to_wait + Duration::from_secs(1)).await;
        let response = jh
            .await
            .unwrap()
            .expect_err("parse_body must have returned an Err.");
        assert_eq!(
            response,
            out_of_range_error(&format!(
                "The request body was not received within {:?} seconds.",
                time_to_wait
            ))
        );
    }
}
