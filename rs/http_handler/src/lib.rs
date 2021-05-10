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
use ic_crypto::CryptoComponent;
use ic_crypto_tls_interfaces::{AllowedClients, SomeOrAllNodes, TlsHandshake};
use ic_crypto_tree_hash::Path;
use ic_interfaces::{
    consensus_pool::ConsensusPoolCache,
    crypto::IngressSigVerifier,
    execution_environment::{ExecutionEnvironment, QueryHandler},
    p2p::IngressEventHandler,
    registry::RegistryClient,
    state_manager::StateReader,
};
use ic_logger::{debug, error, fatal, info, trace, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{CanisterState, NodeTopology, ReplicatedState};
use ic_types::{
    messages::CertificateDelegation,
    messages::{Blob, HttpReadContent, HttpReadState, HttpReadStateResponse, HttpRequestEnvelope},
    time::current_time_and_expiry_time,
    SubnetId,
};
use metrics::HttpHandlerMetrics;
use rand::Rng;
use std::convert::Infallible;
use std::io::{Error, ErrorKind, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::{net::TcpListener, net::TcpStream, sync::Mutex, time::timeout_at, time::Instant};

// Constants defining the limits of the HttpHandler.

// In the HttpHandler we can have at most 'MAX_OUTSTANDING_REQUESTS'
// requests executing concurrently. If we are at the limit, we won't
// accept new tcp connections.
// We choose to use the number of outstanding requests instead of
// outstanding connections or tokio tasks, because ingress of downstream
// systems is measured by number of requests.
const MAX_OUTSTANDING_REQUESTS: usize = 1000;

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

/// The struct that handles incoming HTTP requests for the IC replica.
/// This is collection of thread-safe data members.
pub struct HttpHandler {
    config: Arc<Config>,
    registry_client: Arc<dyn RegistryClient>,
    tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    log: Arc<ReplicaLogger>,
    delegation_from_nns: Option<CertificateDelegation>,
    maliciously_disable_ingress_validation: bool,
    ingress_sender: Arc<dyn IngressEventHandler>,
    query_handler: Arc<dyn QueryHandler<State = ReplicatedState>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    validator: Arc<dyn IngressSigVerifier + Send + Sync>,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    execution_environment:
        Arc<dyn ExecutionEnvironment<State = ReplicatedState, CanisterState = CanisterState>>,
    // Introduction of concurrent request processing caused a regression in FR.
    // This lock restores the serial processing(as a temporary measure) until the
    // regression is investigated further.
    request_processing_lock: Arc<Mutex<()>>,
    subnet_type: SubnetType,
}

// Prepares the server for startup (reading required state, etc).
// Blocks until completion.
#[allow(clippy::too_many_arguments)]
pub fn init_server_blocking(
    config: Arc<Config>,
    ingress_sender: Arc<dyn IngressEventHandler>,
    query_handler: Arc<dyn QueryHandler<State = ReplicatedState>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    registry_client: Arc<dyn RegistryClient>,
    crypto: Arc<CryptoComponent>,
    subnet_id: SubnetId,
    nns_subnet_id: SubnetId,
    log: Arc<ReplicaLogger>,
    consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
    execution_environment: Arc<
        dyn ExecutionEnvironment<State = ReplicatedState, CanisterState = CanisterState>,
    >,
    maliciously_disable_ingress_validation: bool,
    subnet_type: SubnetType,
) -> Result<HttpHandler, Error> {
    info!(log, "Initializing HTTP server...");
    let mut check_count: i32 = 0;
    // Sleep one second between retries, only log every 10th round.
    info!(log, "Waiting for certified state...");
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
    let delegation_from_nns = load_delegation_from_nns_subnet(
        state_reader.as_ref(),
        subnet_id,
        nns_subnet_id,
        log.as_ref(),
    )?;

    Ok(HttpHandler::new(
        config,
        registry_client,
        Arc::clone(&crypto) as Arc<dyn TlsHandshake + Send + Sync>,
        subnet_id,
        subnet_type,
        nns_subnet_id,
        log,
        delegation_from_nns,
        maliciously_disable_ingress_validation,
        ingress_sender,
        query_handler,
        state_reader,
        Arc::clone(&crypto) as Arc<dyn IngressSigVerifier + Send + Sync>,
        consensus_pool_cache,
        execution_environment,
    ))
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
pub async fn start_server(
    metrics_registry: MetricsRegistry,
    http_handler_owned: HttpHandler,
) -> Result<(), Error> {
    let metrics = Arc::new(HttpHandlerMetrics::new(&metrics_registry));
    let http_handler = Arc::new(http_handler_owned);
    let log = http_handler.log.as_ref().clone();
    info!(log, "Starting HTTP server...");

    let listen_addr = http_handler.config.listen_addr;
    // TODO(OR4-60): temporarily listen on [::] so that we accept both IPv4 and
    // IPv6 connections. This requires net.ipv6.bindv6only = 0. Revert this once
    // we have rolled out IPv6 in prometheus and ic_p8s_service_discovery.
    let mut addr = "[::]:8080".parse::<SocketAddr>().unwrap();
    addr.set_port(listen_addr.port());

    info!(log, "Binding HTTP server to address {}", addr);
    let mut tcp_listener = TcpListener::bind(addr).await?;

    // If addr == 0, then a random port will be assigned. In this case it
    // is useful to report the randomly assigned port by writing it to a file.
    let local_addr = tcp_listener.local_addr()?;
    let port_file_path = http_handler.config.port_file_path.clone();
    if let Some(path) = port_file_path {
        create_port_file(path, local_addr.port());
    }

    // IMPORTANT: The system-tests relies on this log message to understand when it
    // can start interacting with the replica. In the future, we plan to
    // have a dedicate instrumentation channel to communicate between the
    // replica and the testing framework, but for now, this is the best we can do.
    info!(log, "Ready for interaction.");

    let http = Http::new();
    let outstanding_requests = ObservableCountingSemaphore::new(
        MAX_OUTSTANDING_REQUESTS,
        Arc::clone(&metrics.inflight_requests),
    );
    loop {
        let http = http.clone();
        let log = log.clone();
        let http_handler = Arc::clone(&http_handler);
        let metrics = Arc::clone(&metrics);
        let request_permit = outstanding_requests.acquire().await;
        match tcp_listener.accept().await {
            Ok((mut tcp_stream, _)) => {
                tokio::task::spawn(async move {
                    // Do a move of the permit so it gets dropped at the end of the scope.
                    let _request_permit_deleter = request_permit;
                    let mut b = [0 as u8; 1];
                    if tcp_stream.peek(&mut b).await.is_ok() && b[0] == 22 {
                        serve_secure_connection(metrics, http_handler, http, tcp_stream, log).await;
                    } else {
                        // Either peeking failed or the first byte is not 22, then
                        // fallback to HTTP.
                        serve_unsecure_connection(metrics, http_handler, http, tcp_stream, log)
                            .await;
                    }
                });
            }
            // Don't exit the loop on a connection error. We will want to
            // continue serving.
            Err(err) => {
                metrics.observe_connection_error(ConnectionError::Accept);
                trace!(log, "Connection error(can't accept) {}", err);
            }
        }
    }
}

impl HttpHandler {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: Arc<Config>,
        registry_client: Arc<dyn RegistryClient>,
        tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
        subnet_id: SubnetId,
        subnet_type: SubnetType,
        nns_subnet_id: SubnetId,
        log: Arc<ReplicaLogger>,
        delegation_from_nns: Option<CertificateDelegation>,
        maliciously_disable_ingress_validation: bool,
        ingress_sender: Arc<dyn IngressEventHandler>,
        query_handler: Arc<dyn QueryHandler<State = ReplicatedState>>,
        state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
        validator: Arc<dyn IngressSigVerifier + Send + Sync>,
        consensus_pool_cache: Arc<dyn ConsensusPoolCache>,
        execution_environment: Arc<
            dyn ExecutionEnvironment<State = ReplicatedState, CanisterState = CanisterState>,
        >,
    ) -> Self {
        Self {
            config,
            registry_client,
            tls_handshake,
            subnet_id,
            subnet_type,
            nns_subnet_id,
            log,
            delegation_from_nns,
            maliciously_disable_ingress_validation,
            ingress_sender,
            query_handler,
            state_reader,
            validator,
            consensus_pool_cache,
            execution_environment,
            request_processing_lock: Arc::new(Mutex::new(())),
        }
    }
}

async fn serve_unsecure_connection(
    metrics: Arc<HttpHandlerMetrics>,
    http_handler: Arc<HttpHandler>,
    http: Http,
    tcp_stream: TcpStream,
    log: ReplicaLogger,
) {
    let metrics_svc = Arc::clone(&metrics);
    let aservice_fn = service_fn(move |request| {
        let http_handler = Arc::clone(&http_handler);
        let metrics_svc = Arc::clone(&metrics_svc);
        // start recording overall latency per request
        let request_start_time = Instant::now();
        async move {
            Ok::<_, Infallible>(
                route(
                    metrics_svc,
                    request_start_time,
                    http_handler,
                    AppLayer::HTTP,
                    request,
                )
                .await,
            )
        }
    });
    if let Err(err) = http.serve_connection(tcp_stream, aservice_fn).await {
        metrics.observe_connection_error(ConnectionError::ServingHttpConnection);
        trace!(
            log,
            "Connection error(can't serve HTTP connection): {}",
            err
        );
    }
}

async fn serve_secure_connection(
    metrics: Arc<HttpHandlerMetrics>,
    http_handler: Arc<HttpHandler>,
    http: Http,
    tcp_stream: TcpStream,
    log: ReplicaLogger,
) {
    let http_handler_svc = Arc::clone(&http_handler);
    let metrics_svc = Arc::clone(&metrics);
    let aservice_fn = service_fn(move |request| {
        let http_handler_svc = Arc::clone(&http_handler_svc);
        let metrics_svc = Arc::clone(&metrics_svc);
        // start recording overall latency per request
        let request_start_time = Instant::now();
        async move {
            Ok::<_, Infallible>(
                route(
                    metrics_svc,
                    request_start_time,
                    http_handler_svc,
                    AppLayer::HTTPS,
                    request,
                )
                .await,
            )
        }
    });

    let mut clients_certs = Vec::new();
    let mut clients_certs_exist = false;
    if let Some(http_handler_clients_x509_cert) = http_handler.config.clients_x509_cert.clone() {
        clients_certs.push(http_handler_clients_x509_cert);
        clients_certs_exist = true;
    }
    let tls_handshake_result = {
        let allowed_clients = AllowedClients::new(SomeOrAllNodes::All, clients_certs)
            .expect("invalid allowed clients");
        let registry_version = http_handler.registry_client.get_latest_version();
        http_handler
            .tls_handshake
            .perform_tls_server_handshake_temp_with_optional_client_auth(
                tcp_stream,
                allowed_clients,
                registry_version,
            )
            .await
    };
    match tls_handshake_result {
        Err(err) => {
            metrics.observe_connection_error(ConnectionError::TlsHandshake);
            trace!(log, "Connection error(tls handshake): {}", err);
        }
        Ok((tls_stream, peer)) => {
            if clients_certs_exist && peer == ic_crypto_tls_interfaces::Peer::Unauthenticated {
                metrics.observe_connection_error(ConnectionError::ClientAuthentication);
                trace!(log, "Connection error(unauthenticated client).");
            } else if let Err(err) = http.serve_connection(tls_stream, aservice_fn).await {
                metrics.observe_connection_error(ConnectionError::ServingHttpsConnection);
                trace!(
                    log,
                    "Connection error(can't serve HTTPs connection): {}",
                    err
                );
            }
        }
    };
}

fn is_blocking_request(request_type: &RequestType) -> bool {
    match request_type {
        RequestType::CatchUpPackage | RequestType::Options | RequestType::RedirectToDashboard => {
            false
        }
        _ => true,
    }
}

async fn route(
    metrics: Arc<HttpHandlerMetrics>,
    request_start_time: Instant,
    http_handler: Arc<HttpHandler>,
    app_layer: AppLayer,
    request: Request<Body>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();
    match validate_parts(parts) {
        Ok(req_type) => {
            metrics.observe_requests_per_app_layer(&req_type, &app_layer);
            match parse_body(
                &req_type,
                body,
                Instant::now() + Duration::from_secs(MAX_REQUEST_TIMEOUT_SECS),
            )
            .await
            {
                Ok(parsed_body) => {
                    if is_blocking_request(&req_type) {
                        // Serialize the processing
                        let _processing_lock = http_handler.request_processing_lock.lock().await;
                        match tokio::task::spawn_blocking({
                            let http_handler = Arc::clone(&http_handler);
                            let metrics = Arc::clone(&metrics);
                            let request_type = req_type;
                            move || {
                                route_blocking(
                                    metrics,
                                    request_start_time,
                                    http_handler,
                                    parsed_body,
                                    request_type,
                                )
                            }
                        })
                        .await
                        {
                            Err(_err) => {
                                metrics.observe_internal_error(
                                    &req_type,
                                    InternalError::ConcurrentTaskExecution,
                                );
                                common::empty_response()
                            }
                            Ok(response) => response,
                        }
                    } else {
                        route_non_blocking(
                            metrics,
                            request_start_time,
                            http_handler,
                            parsed_body,
                            req_type,
                        )
                    }
                }
                Err(err) => err,
            }
        }
        Err(err) => err,
    }
}

fn route_blocking(
    metrics: Arc<HttpHandlerMetrics>,
    request_start_time: Instant,
    http_handler: Arc<HttpHandler>,
    parsed_body: Vec<u8>,
    request_type: RequestType,
) -> Response<Body> {
    let (http_resp, api_req_type) = match request_type {
        RequestType::Read => read::handle(
            http_handler.log.as_ref(),
            http_handler.delegation_from_nns.clone(),
            http_handler.query_handler.as_ref(),
            http_handler.state_reader.as_ref(),
            http_handler.validator.as_ref(),
            http_handler.registry_client.get_latest_version(),
            parsed_body,
            metrics.as_ref(),
        ),
        RequestType::Submit => submit::handle(
            http_handler.log.as_ref(),
            http_handler.subnet_id,
            http_handler.registry_client.as_ref(),
            http_handler.maliciously_disable_ingress_validation,
            http_handler.ingress_sender.as_ref(),
            http_handler.state_reader.as_ref(),
            http_handler.validator.as_ref(),
            http_handler.execution_environment.as_ref(),
            parsed_body,
            metrics.as_ref(),
        ),
        RequestType::Status => (
            status::handle(
                http_handler.log.as_ref(),
                http_handler.config.as_ref(),
                http_handler.nns_subnet_id,
                http_handler.state_reader.as_ref(),
            ),
            ApiReqType::Unknown,
        ),
        RequestType::Dashboard => (
            dashboard::handle(
                http_handler.config.as_ref(),
                http_handler.state_reader.as_ref(),
                http_handler.subnet_type,
            ),
            ApiReqType::Unknown,
        ),
        _ => {
            metrics.observe_internal_error(&request_type, InternalError::Routing);
            (common::empty_response(), ApiReqType::Unknown)
        }
    };
    // record request latency along dimensions (request type, status code, api
    // request type)
    metrics
        .requests
        .with_label_values(&[
            &request_type.to_string(),
            &http_resp.status().to_string(),
            &api_req_type.to_string(),
        ])
        .observe(request_start_time.elapsed().as_secs_f64());
    http_resp
}

fn route_non_blocking(
    metrics: Arc<HttpHandlerMetrics>,
    request_start_time: Instant,
    http_handler: Arc<HttpHandler>,
    parsed_body: Vec<u8>,
    request_type: RequestType,
) -> Response<Body> {
    let (http_resp, api_req_type) = match request_type {
        RequestType::CatchUpPackage => (
            catch_up_package::handle(http_handler.consensus_pool_cache.as_ref(), parsed_body),
            ApiReqType::Unknown,
        ),
        RequestType::RedirectToDashboard => (redirect_to_dashboard(), ApiReqType::Unknown),
        RequestType::Options => (
            common::make_response(StatusCode::NO_CONTENT, ""),
            ApiReqType::Unknown,
        ),
        _ => {
            metrics.observe_internal_error(&request_type, InternalError::Routing);
            (common::empty_response(), ApiReqType::Unknown)
        }
    };
    // record request latency along dimensions (request type, status code, api
    // request type)
    metrics
        .requests
        .with_label_values(&[
            &request_type.to_string(),
            &http_resp.status().to_string(),
            &api_req_type.to_string(),
        ])
        .observe(request_start_time.elapsed().as_secs_f64());
    http_resp
}

// Fetches a delegation from the NNS subnet to allow this subnet to issue
// certificates on its behalf. On the NNS subnet this method is a no-op.
fn load_delegation_from_nns_subnet(
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
            .header("Content-Type", "application/cbor")
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
    req_type: &RequestType,
    mut body: Body,
    deadline: Instant,
) -> Result<Vec<u8>, Response<Body>> {
    // Read "content-length" bytes
    // Parse the body only when needed.
    match req_type {
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
                        return Err(Response::builder()
                            .status(StatusCode::REQUEST_TIMEOUT)
                            .body(Body::from(format!(
                                "The request was not received within {} seconds.",
                                MAX_REQUEST_TIMEOUT_SECS
                            )))
                            .unwrap());
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
fn validate_parts(parts: http::request::Parts) -> Result<RequestType, Response<Body>> {
    use http::{method::Method, HeaderMap};
    match parts.method {
        Method::POST => {
            // Check that we have a content-type header
            fn is_cbor(hs: &HeaderMap) -> bool {
                let view = hs.get_all(http::header::CONTENT_TYPE);
                view.iter()
                    .any(|value| value.to_str().unwrap().to_lowercase() == "application/cbor")
            };

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
    Response::builder()
        .status(StatusCode::FOUND)
        .header(hyper::header::LOCATION, HTTP_DASHBOARD_URL_PATH)
        .body(Body::from(""))
        .unwrap()
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
        tokio::time::delay_until(deadline + Duration::from_secs(1)).await;
        let response = jh
            .await
            .unwrap()
            .expect_err("parse_body must have returned an Err.");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }
}
