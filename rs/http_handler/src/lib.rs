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
mod read;
mod status;
mod submit;
mod types;

use crate::types::*;
use futures_util::stream::StreamExt;
use hyper::{server::conn::Http, service::service_fn};
use hyper::{Body, Request, Response, StatusCode};
use ic_base_thread::ObservableCountingSemaphore;
use ic_config::http_handler::Config;
use ic_crypto_tls_interfaces::{AllowedClients, SomeOrAllNodes, TlsHandshake};
use ic_crypto_tree_hash::Path;
use ic_interfaces::execution_environment::IngressMessageFilter;
use ic_interfaces::{
    consensus_pool::ConsensusPoolCache, crypto::IngressSigVerifier,
    execution_environment::QueryHandler, p2p::IngressEventHandler, registry::RegistryClient,
    state_manager::StateReader,
};
use ic_logger::{debug, error, fatal, info, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{NodeTopology, ReplicatedState};
use ic_types::{
    malicious_flags::MaliciousFlags,
    messages::CertificateDelegation,
    messages::{
        Blob, HttpReadContent, HttpReadState, HttpReadStateResponse, HttpRequestEnvelope,
        ReplicaHealthStatus,
    },
    time::current_time_and_expiry_time,
    SubnetId,
};
use metrics::HttpHandlerMetrics;
use rand::Rng;
use std::collections::HashSet;
use std::convert::Infallible;
use std::io::{Error, ErrorKind, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use tempfile::NamedTempFile;

use tokio::{net::TcpListener, net::TcpStream, time::timeout, time::timeout_at, time::Instant};

// Constants defining the limits of the HttpHandler.

// In the HttpHandler we can have at most 'MAX_OUTSTANDING_CONNECTIONS'
// live TCP connections. If we are at the limit, we won't
// accept new TCP connections.
const MAX_OUTSTANDING_CONNECTIONS: usize = 30000;

// The maximum time we should wait for a peeking the first bytes on a TCP
// connection. Effectively, if we can't read the first bytes within the
// timeout the connection is broken.
const MAX_TCP_PEEK_TIMEOUT_SECS: u64 = 5;

// Request with body size bigger than 'MAX_REQUEST_SIZE_BYTES' will be rejected
// and appropriate error code will be returned to the user.
const MAX_REQUEST_SIZE_BYTES: usize = 5 * 1024 * 1024; // 5MB

// If the request is not received/parsed within 'MAX_REQUEST_TIMEOUT_SECS', then
// the request will be rejected and appropriate error code will be returned to
// the user.
const MAX_REQUEST_TIMEOUT_SECS: u64 = 5 * 60; // 5 min

// Number of times to try fetching the root delegation before giving up.
const MAX_FETCH_DELEGATION_ATTEMPTS: u8 = 10;

const HTTP_DASHBOARD_URL_PATH: &str = "/_/dashboard";

// Placeholder used when we can't determine the approriate prometheus label.
const UNKNOWN_LABEL: &str = "unknown";

/// The struct that handles incoming HTTP requests for the IC replica.
/// This is collection of thread-safe data members.
struct HttpHandler {
    config: Config,
    registry_client: Arc<dyn RegistryClient>,
    tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    log: ReplicaLogger,
    ingress_sender: Arc<dyn IngressEventHandler>,
    query_handler: Arc<dyn QueryHandler<State = ReplicatedState>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    validator: Arc<dyn IngressSigVerifier + Send + Sync>,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    ingress_message_filter: Arc<dyn IngressMessageFilter<State = ReplicatedState>>,
    subnet_type: SubnetType,

    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    health_status: Arc<RwLock<ReplicaHealthStatus>>,
    malicious_flags: MaliciousFlags,
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
    ingress_sender: Arc<dyn IngressEventHandler>,
    query_handler: Arc<dyn QueryHandler<State = ReplicatedState>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    registry_client: Arc<dyn RegistryClient>,
    tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
    ingress_verifier: Arc<dyn IngressSigVerifier + Send + Sync>,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    log: ReplicaLogger,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    ingress_message_filter: Arc<dyn IngressMessageFilter<State = ReplicatedState>>,
    subnet_type: SubnetType,
    malicious_flags: MaliciousFlags,
) -> Result<(), Error> {
    let metrics = Arc::new(HttpHandlerMetrics::new(&metrics_registry));

    let http_handler = Arc::new(HttpHandler::new(
        config,
        registry_client,
        tls_handshake,
        subnet_id,
        subnet_type,
        nns_subnet_id,
        log.clone(),
        ingress_sender,
        query_handler,
        state_reader,
        ingress_verifier,
        consensus_pool_cache,
        ingress_message_filter,
        malicious_flags,
    ));

    info!(log, "Starting HTTP server...");

    let listen_addr = http_handler.config.listen_addr;
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
    let port_file_path = http_handler.config.port_file_path.clone();
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

    let http = Http::new();
    let outstanding_connections = ObservableCountingSemaphore::new(
        MAX_OUTSTANDING_CONNECTIONS,
        Arc::clone(&metrics.connections),
    );
    loop {
        let http = http.clone();
        let log = log.clone();
        let http_handler = Arc::clone(&http_handler);
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
                    match timeout(
                        Duration::from_secs(MAX_TCP_PEEK_TIMEOUT_SECS),
                        tcp_stream.peek(&mut b),
                    )
                    .await
                    {
                        Ok(tcp_stream_peek_result) => match tcp_stream_peek_result {
                            Ok(_) => {
                                if b[0] == 22 {
                                    serve_secure_connection(
                                        metrics,
                                        http_handler,
                                        http,
                                        tcp_stream,
                                        connection_start_time,
                                        log,
                                    )
                                    .await;
                                } else {
                                    // Either peeking failed or the first byte is not 22, then
                                    // fallback to HTTP.
                                    serve_unsecure_connection(
                                        metrics,
                                        http_handler,
                                        http,
                                        tcp_stream,
                                        connection_start_time,
                                        log,
                                    )
                                    .await;
                                }
                            }
                            Err(err) => {
                                warn!(log, "Connection error (can't peek) {}", err);
                                metrics.observe_connection_error(
                                    ConnectionError::Peek,
                                    connection_start_time,
                                );
                            }
                        },
                        Err(err) => {
                            metrics.observe_connection_error(
                                ConnectionError::PeekTimeout,
                                connection_start_time,
                            );
                            warn!(
                                log,
                                "Connection error (tcp peeking timeout after {}s) {}",
                                MAX_TCP_PEEK_TIMEOUT_SECS,
                                err
                            );
                        }
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
        tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
        subnet_id: SubnetId,
        subnet_type: SubnetType,
        nns_subnet_id: SubnetId,
        log: ReplicaLogger,
        ingress_sender: Arc<dyn IngressEventHandler>,
        query_handler: Arc<dyn QueryHandler<State = ReplicatedState>>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        validator: Arc<dyn IngressSigVerifier + Send + Sync>,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        ingress_message_filter: Arc<dyn IngressMessageFilter<State = ReplicatedState>>,
        malicious_flags: MaliciousFlags,
    ) -> Self {
        Self {
            config,
            registry_client,
            tls_handshake,
            subnet_id,
            subnet_type,
            nns_subnet_id,
            log,
            ingress_sender,
            query_handler,
            state_reader,
            validator,
            consensus_pool_cache,
            ingress_message_filter,
            delegation_from_nns: Arc::new(RwLock::new(None)),
            health_status: Arc::new(RwLock::new(ReplicaHealthStatus::Starting)),
            malicious_flags,
        }
    }
}

async fn serve_unsecure_connection(
    metrics: Arc<HttpHandlerMetrics>,
    http_handler: Arc<HttpHandler>,
    http: Http,
    tcp_stream: TcpStream,
    connection_start_time: Instant,
    log: ReplicaLogger,
) {
    let metrics_svc = Arc::clone(&metrics);
    let aservice_fn = service_fn(move |request| {
        let http_handler = Arc::clone(&http_handler);
        let metrics_svc = Arc::clone(&metrics_svc);
        async move {
            Ok::<_, Infallible>(route(metrics_svc, http_handler, AppLayer::Http, request).await)
        }
    });
    if let Err(err) = http.serve_connection(tcp_stream, aservice_fn).await {
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
    metrics: Arc<HttpHandlerMetrics>,
    http_handler: Arc<HttpHandler>,
    http: Http,
    tcp_stream: TcpStream,
    connection_start_time: Instant,
    log: ReplicaLogger,
) {
    let http_handler_svc = Arc::clone(&http_handler);
    let metrics_svc = Arc::clone(&metrics);
    let aservice_fn = service_fn(move |request| {
        let http_handler_svc = Arc::clone(&http_handler_svc);
        let metrics_svc = Arc::clone(&metrics_svc);
        async move {
            Ok::<_, Infallible>(
                route(metrics_svc, http_handler_svc, AppLayer::Https, request).await,
            )
        }
    });

    let mut clients_certs = HashSet::new();
    let mut clients_certs_exist = false;
    if let Some(http_handler_clients_x509_cert) = http_handler.config.clients_x509_cert.clone() {
        clients_certs.insert(http_handler_clients_x509_cert);
        clients_certs_exist = true;
    }
    let allowed_clients =
        AllowedClients::new(SomeOrAllNodes::All, clients_certs).expect("invalid allowed clients");
    let registry_version = http_handler.registry_client.get_latest_version();
    match http_handler
        .tls_handshake
        .perform_tls_server_handshake_temp_with_optional_client_auth(
            tcp_stream,
            allowed_clients,
            registry_version,
        )
        .await
    {
        Err(err) => {
            metrics.observe_connection_error(ConnectionError::TlsHandshake, connection_start_time);
            warn!(log, "Connection error (TLS handshake): {}", err);
        }
        Ok((tls_stream, peer)) => {
            if clients_certs_exist && peer == ic_crypto_tls_interfaces::Peer::Unauthenticated {
                metrics.observe_connection_error(
                    ConnectionError::ClientAuthentication,
                    connection_start_time,
                );
                warn!(log, "Connection error (unauthenticated client).");
            } else if let Err(err) = http.serve_connection(tls_stream, aservice_fn).await {
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
    };
}

fn needs_all_preconditions(request_type: &RequestType) -> bool {
    !matches!(
        request_type,
        RequestType::CatchUpPackage
            | RequestType::Options
            | RequestType::RedirectToDashboard
            | RequestType::Dashboard
            | RequestType::Status
    )
}

async fn route(
    metrics: Arc<HttpHandlerMetrics>,
    http_handler: Arc<HttpHandler>,
    app_layer: AppLayer,
    request: Request<Body>,
) -> Response<Body> {
    // Start recording request duration.
    let request_start_time = Instant::now();

    let (parts, body) = request.into_parts();
    let (request_type, (response, api_req_type)) = match validate_parts(&parts) {
        Ok(request_type) => {
            // Don't process requests for which preconditions are not met.
            if needs_all_preconditions(&request_type)
                && *http_handler.health_status.read().unwrap() != ReplicaHealthStatus::Healthy
            {
                (
                    request_type.as_str().to_string(),
                    (
                        common::make_response(
                            StatusCode::PRECONDITION_FAILED,
                            "Replica is starting. Check the /api/v2/status for more information.",
                        ),
                        ApiReqType::Unknown,
                    ),
                )
            } else {
                match parse_body(
                    &request_type,
                    body,
                    Instant::now() + Duration::from_secs(MAX_REQUEST_TIMEOUT_SECS),
                )
                .await
                {
                    Ok(parsed_body) => (
                        request_type.as_str().to_string(),
                        route_to_handlers(
                            Arc::clone(&metrics),
                            http_handler,
                            parsed_body,
                            request_type,
                        )
                        .await,
                    ),
                    Err(err) => (
                        request_type.as_str().to_string(),
                        (err, ApiReqType::Unknown),
                    ),
                }
            }
        }
        Err(err) => (UNKNOWN_LABEL.to_string(), (err, ApiReqType::Unknown)),
    };
    metrics.observe_request(
        &request_start_time,
        &request_type,
        &api_req_type,
        &response.status(),
        &app_layer,
        &parts.version,
    );
    response
}

async fn route_to_handlers(
    metrics: Arc<HttpHandlerMetrics>,
    http_handler: Arc<HttpHandler>,
    parsed_body: Vec<u8>,
    request_type: RequestType,
) -> (Response<Body>, ApiReqType) {
    match request_type {
        RequestType::Read => {
            read::handle(
                &http_handler.log,
                &http_handler.delegation_from_nns,
                http_handler.query_handler.as_ref(),
                http_handler.state_reader.as_ref(),
                http_handler.validator.as_ref(),
                http_handler.registry_client.get_latest_version(),
                parsed_body,
                metrics.as_ref(),
                &http_handler.malicious_flags,
            )
            .await
        }
        RequestType::Submit => {
            submit::handle(
                metrics,
                http_handler.log.clone(),
                http_handler.subnet_id,
                Arc::clone(&http_handler.registry_client),
                Arc::clone(&http_handler.state_reader),
                Arc::clone(&http_handler.validator),
                Arc::clone(&http_handler.ingress_sender),
                http_handler.malicious_flags.clone(),
                Arc::clone(&http_handler.ingress_message_filter),
                parsed_body,
            )
            .await
        }
        RequestType::Status => (
            status::handle(
                &http_handler.log,
                &http_handler.config,
                http_handler.nns_subnet_id,
                http_handler.state_reader.as_ref(),
                http_handler.health_status.read().unwrap().clone(),
            ),
            ApiReqType::Unknown,
        ),
        RequestType::Dashboard => (
            dashboard::handle(
                &http_handler.config,
                http_handler.state_reader.as_ref(),
                http_handler.subnet_type,
            ),
            ApiReqType::Unknown,
        ),
        RequestType::CatchUpPackage => (
            catch_up_package::handle(http_handler.consensus_pool_cache.as_ref(), parsed_body),
            ApiReqType::Unknown,
        ),
        RequestType::RedirectToDashboard => (redirect_to_dashboard(), ApiReqType::Unknown),
        RequestType::Options => (
            common::make_response(StatusCode::NO_CONTENT, ""),
            ApiReqType::Unknown,
        ),
    }
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

        let log_err_and_backoff = |err: reqwest::Error| {
            // Fetching the NNS delegation failed. Do a random backoff and try again.
            let mut rng = rand::thread_rng();
            let backoff = Duration::from_secs(rng.gen_range(1..15));
            error!(
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
                    paths: vec![Path::new(vec![
                        b"subnet".into(),
                        subnet_id.get().into(),
                        b"public_key".into(),
                    ])],
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
            .header(hyper::header::CONTENT_TYPE, "application/cbor")
            .body(body)
            .send()
        {
            Ok(res) => res.bytes(),
            Err(err) => {
                log_err_and_backoff(err);
                continue;
            }
        };

        match raw_response_res {
            Ok(raw_response) => {
                debug!(log, "Response from nns subnet: {:?}", raw_response);

                let response: HttpReadStateResponse = serde_cbor::from_slice(&raw_response)
                    .expect("Incomprehensible response when fetching delegation from nns subnet");

                let delegation = CertificateDelegation {
                    subnet_id: Blob(subnet_id.get().to_vec()),
                    certificate: response.certificate,
                };

                info!(log, "Setting NNS delegation to: {:?}", delegation);
                return Ok(Some(delegation));
            }
            Err(err) => {
                // Fetching the NNS delegation failed. Do a random backoff and try again.
                log_err_and_backoff(err);
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
    request_type: &RequestType,
    mut body: Body,
    deadline: Instant,
) -> Result<Vec<u8>, Response<Body>> {
    // Read "content-length" bytes
    // Parse the body only when needed.
    match request_type {
        RequestType::Options | RequestType::RedirectToDashboard => Ok(Vec::new()),
        _ => {
            let mut parsed_body = Vec::<u8>::new();
            // Timeout when we are waiting for the next chunk because this wait depends on
            // the user.
            loop {
                match timeout_at(deadline, body.next()).await {
                    Ok(chunk_option) => match chunk_option {
                        Some(chunk) => match chunk {
                            Err(err) => {
                                return Err(common::make_response(
                                    StatusCode::BAD_REQUEST,
                                    format!("Unexpected error while reading request: {}", err)
                                        .as_str(),
                                ));
                            }
                            Ok(bytes) => {
                                if parsed_body.len() + bytes.len() > MAX_REQUEST_SIZE_BYTES {
                                    return Err(common::make_response(
                                        StatusCode::BAD_REQUEST,
                                        format!(
                                            "Request is too big. Max allowed size in bytes is: {}",
                                            MAX_REQUEST_SIZE_BYTES
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
                        let mut response = Response::new(Body::from(format!(
                            "The request was not received within {} seconds.",
                            MAX_REQUEST_TIMEOUT_SECS
                        )));
                        *response.status_mut() = StatusCode::REQUEST_TIMEOUT;
                        return Err(response);
                    }
                }
            }
        }
    }
}

// Here we perform a few checks:
//  * Is the method correct, e.g. POST?
//  * Is there a "content-type: application/cbor" header?
//  * Is the path correct?
fn validate_parts(parts: &http::request::Parts) -> Result<RequestType, Response<Body>> {
    use http::{method::Method, HeaderMap};
    match parts.method {
        Method::POST => {
            // Check that we have a content-type header
            fn is_cbor(hs: &HeaderMap) -> bool {
                let view = hs.get_all(http::header::CONTENT_TYPE);
                view.iter()
                    .any(|value| value.to_str().unwrap().to_lowercase() == "application/cbor")
            }

            if !is_cbor(&parts.headers) {
                return Err(common::make_response(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Bad content-type, expecting application/cbor",
                ));
            }

            // Check the path
            let path = parts.uri.path();
            match *path.split('/').collect::<Vec<&str>>().as_slice() {
                ["", "api", "v1", "submit"] => Ok(RequestType::Submit),
                ["", "api", "v1", "read"] => Ok(RequestType::Read),
                ["", "api", "v2", "canister", _, "call"] => Ok(RequestType::Submit),
                ["", "api", "v2", "canister", _, "query"] => Ok(RequestType::Read),
                ["", "api", "v2", "canister", _, "read_state"] => Ok(RequestType::Read),
                ["", "_", "catch_up_package"] => Ok(RequestType::CatchUpPackage),
                _ => Err(common::make_response(StatusCode::NOT_FOUND, "")),
            }
        }
        Method::GET => match parts.uri.path() {
            "/api/v1/status" => Ok(RequestType::Status),
            "/api/v2/status" => Ok(RequestType::Status),
            "/" | "/_/" => Ok(RequestType::RedirectToDashboard),
            HTTP_DASHBOARD_URL_PATH => Ok(RequestType::Dashboard),
            _ => Err(common::make_response(StatusCode::NOT_FOUND, "")),
        },
        Method::OPTIONS => Ok(RequestType::Options),
        _ => Err(common::make_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "Unsupported method",
        )),
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
        let deadline = Instant::now() + Duration::from_secs(5 * 60);
        let (mut sender, body) = Body::channel();
        assert!(sender
            .send_data(bytes::Bytes::from("hello world"))
            .await
            .is_ok());
        // We need to drop the channel so 'parse_body' will know there aren't any new
        // chunks. If we remove this line the test should run forever.
        std::mem::drop(sender);
        assert_eq!(
            parse_body(&RequestType::Submit, body, deadline).await.ok(),
            Some(Vec::<u8>::from("hello world"))
        );
    }

    #[tokio::test]
    async fn test_stop_and_return_error_when_parsing_big_body() {
        let deadline = Instant::now() + Duration::from_secs(5 * 60);
        let (mut sender, body) = Body::channel();
        let chunk_size: usize = 1024;
        let rand_string: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(chunk_size)
            .map(char::from)
            .collect();

        let jh = tokio::task::spawn(parse_body(&RequestType::Submit, body, deadline));

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
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        // Check we can't send more data. The other end of the channel - the body - is
        // dropped.
        assert!(sender
            .send_data(bytes::Bytes::from(rand_string.clone()))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_time_out_during_body_parsing() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut sender, body) = Body::channel();
        let jh = tokio::task::spawn(parse_body(&RequestType::Submit, body, deadline));
        assert!(sender
            .send_data(bytes::Bytes::from("hello world"))
            .await
            .is_ok());
        // If we drop the sender here the test will fail because parse_body has all the
        // chunks so it won't timeout.
        tokio::time::sleep_until(deadline + Duration::from_secs(1)).await;
        let response = jh
            .await
            .unwrap()
            .expect_err("parse_body must have returned an Err.");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }
}
