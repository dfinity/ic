//! This is the entry point of the Internet Computer. This deals with
//! accepting HTTP connections, parsing messages and forwarding them to the
//! correct components.
//!
//! As much as possible the naming of structs in this module should match the
//! naming used in the [Interface
//! Specification](https://sdk.dfinity.org/docs/interface-spec/index.html)
mod body;
mod catch_up_package;
mod common;
mod dashboard;
mod health_status_refresher;
mod pprof;
mod query;
mod read_state;
mod state_reader_executor;
mod status;
mod threads;
mod types;

cfg_if::cfg_if! {
    if #[cfg(feature = "fuzzing_code")] {
        pub mod validator_executor;
        pub mod metrics;
        pub mod call;
    } else {
        mod validator_executor;
        mod metrics;
        mod call;
    }
}

use crate::{
    body::BodyReceiverLayer,
    call::CallService,
    catch_up_package::CatchUpPackageService,
    common::{
        get_cors_headers, get_root_threshold_public_key, make_plaintext_response,
        map_box_error_to_response,
    },
    dashboard::DashboardService,
    health_status_refresher::HealthStatusRefreshLayer,
    metrics::{
        LABEL_REQUEST_TYPE, LABEL_STATUS, REQUESTS_LABEL_NAMES, REQUESTS_NUM_LABELS, STATUS_ERROR,
        STATUS_SUCCESS,
    },
    pprof::{PprofFlamegraphService, PprofHomeService, PprofProfileService},
    query::QueryService,
    read_state::{canister::CanisterReadStateService, subnet::SubnetReadStateService},
    state_reader_executor::StateReaderExecutor,
    status::StatusService,
    types::*,
    validator_executor::ValidatorExecutor,
};
use byte_unit::Byte;
use bytes::Bytes;
use crossbeam::{atomic::AtomicCell, channel::Sender};
use http::method::Method;
use hyper::{server::conn::Http, Body, Request, Response, StatusCode};
use ic_async_utils::{receive_body, start_tcp_listener};
use ic_certification::validate_subnet_delegation_certificate;
use ic_config::http_handler::Config;
use ic_crypto_interfaces_sig_verification::IngressSigVerifier;
use ic_crypto_tls_interfaces::{TlsHandshake, TlsStream};
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
use ic_types::{
    artifact::UnvalidatedArtifactMutation,
    artifact_kind::IngressArtifact,
    malicious_flags::MaliciousFlags,
    messages::{
        Blob, Certificate, CertificateDelegation, HttpReadState, HttpReadStateContent,
        HttpReadStateResponse, HttpRequestEnvelope, QueryResponseHash, ReplicaHealthStatus,
    },
    time::expiry_time_from_now,
    NodeId, PrincipalId, SubnetId,
};
use metrics::{HttpHandlerMetrics, LABEL_UNKNOWN};
use rand::Rng;
use std::{
    convert::{Infallible, TryFrom},
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, RwLock},
    time::Duration,
};
use strum::{Display, IntoStaticStr};
use tempfile::NamedTempFile;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout, Instant};
use tokio_io_timeout::TimeoutStream;
use tower::{
    limit::GlobalConcurrencyLimitLayer, service_fn, util::BoxCloneService, BoxError, Service,
    ServiceBuilder, ServiceExt,
};

const HTTP_DASHBOARD_URL_PATH: &str = "/_/dashboard";
const CONTENT_TYPE_CBOR: &str = "application/cbor";

#[derive(Debug, Clone, PartialEq)]
pub struct HttpError {
    pub status: StatusCode,
    pub message: String,
}

pub(crate) type EndpointService = BoxCloneService<Request<Bytes>, Response<Body>, Infallible>;

/// Struct that holds all endpoint services.
#[derive(Clone)]
struct HttpHandler {
    call_service: EndpointService,
    query_service: EndpointService,
    catchup_service: EndpointService,
    dashboard_service: EndpointService,
    status_service: EndpointService,
    canister_read_state_service: EndpointService,
    subnet_read_state_service: EndpointService,
    pprof_home_service: EndpointService,
    pprof_profile_service: EndpointService,
    pprof_flamegraph_service: EndpointService,
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
    state_reader_executor: StateReaderExecutor,
    delegation_from_nns: Arc<RwLock<Option<CertificateDelegation>>>,
    health_status: Arc<AtomicCell<ReplicaHealthStatus>>,
    rt_handle: tokio::runtime::Handle,
    tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
) {
    let rt_handle_clone = rt_handle.clone();
    rt_handle.spawn(async move {
        info!(log, "Initializing HTTP server...");
        // Sleep one second between retries, only log every 10th round.
        info!(log, "Waiting for certified state...");
        metrics
            .health_status_transitions_total
            .with_label_values(&[
                &health_status.load().to_string(),
                &ReplicaHealthStatus::WaitingForCertifiedState.to_string(),
            ])
            .inc();
        health_status.store(ReplicaHealthStatus::WaitingForCertifiedState);

        while common::get_latest_certified_state(&state_reader_executor)
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
            tls_handshake.as_ref(),
        )
        .await;
        if let Some(delegation) = loaded_delegation {
            *delegation_from_nns.write().unwrap() = Some(delegation);
        }
        metrics
            .health_status_transitions_total
            .with_label_values(&[
                &health_status.load().to_string(),
                &ReplicaHealthStatus::Healthy.to_string(),
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
#[allow(clippy::too_many_arguments)]
pub fn start_server(
    rt_handle: tokio::runtime::Handle,
    metrics_registry: &MetricsRegistry,
    config: Config,
    ingress_filter: IngressFilterService,
    query_execution_service: QueryExecutionService,
    ingress_throttler: Arc<RwLock<dyn IngressPoolThrottler + Send + Sync>>,
    ingress_tx: Sender<UnvalidatedArtifactMutation<IngressArtifact>>,
    state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    query_signer: Arc<dyn BasicSigner<QueryResponseHash> + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
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
) {
    let listen_addr = config.listen_addr;
    info!(log, "Starting HTTP server...");

    let _enter = rt_handle.enter();
    // TODO(OR4-60): temporarily listen on [::] so that we accept both IPv4 and
    // IPv6 connections. This requires net.ipv6.bindv6only = 0. Revert this once
    // we have rolled out IPv6 in prometheus and ic_p8s_service_discovery.
    let mut addr = "[::]:8080".parse::<SocketAddr>().unwrap();
    addr.set_port(listen_addr.port());
    let tcp_listener = start_tcp_listener(addr);

    if !AtomicCell::<ReplicaHealthStatus>::is_lock_free() {
        error!(log, "Replica health status uses locks instead of atomics.");
    }
    let metrics = HttpHandlerMetrics::new(metrics_registry);

    let delegation_from_nns = Arc::new(RwLock::new(delegation_from_nns));
    let health_status = Arc::new(AtomicCell::new(ReplicaHealthStatus::Starting));
    let state_reader_executor = StateReaderExecutor::new(state_reader);
    let call_service = CallService::new_service(
        config.clone(),
        log.clone(),
        metrics.clone(),
        node_id,
        subnet_id,
        Arc::clone(&registry_client),
        ValidatorExecutor::new(
            Arc::clone(&registry_client),
            ingress_verifier.clone(),
            &malicious_flags,
            log.clone(),
        ),
        ingress_filter,
        ingress_throttler,
        ingress_tx,
    );
    let query_service = QueryService::new_service(
        config.clone(),
        log.clone(),
        metrics.clone(),
        query_signer,
        node_id,
        Arc::clone(&health_status),
        Arc::clone(&delegation_from_nns),
        ValidatorExecutor::new(
            Arc::clone(&registry_client),
            ingress_verifier.clone(),
            &malicious_flags,
            log.clone(),
        ),
        Arc::clone(&registry_client),
        query_execution_service,
    );
    let canister_read_state_service = CanisterReadStateService::new_service(
        config.clone(),
        log.clone(),
        metrics.clone(),
        Arc::clone(&health_status),
        Arc::clone(&delegation_from_nns),
        state_reader_executor.clone(),
        ValidatorExecutor::new(
            Arc::clone(&registry_client),
            ingress_verifier.clone(),
            &malicious_flags,
            log.clone(),
        ),
        Arc::clone(&registry_client),
    );
    let subnet_read_state_service = SubnetReadStateService::new_service(
        config.clone(),
        log.clone(),
        metrics.clone(),
        Arc::clone(&health_status),
        Arc::clone(&delegation_from_nns),
        state_reader_executor.clone(),
    );
    let status_service = StatusService::new_service(
        config.clone(),
        log.clone(),
        nns_subnet_id,
        Arc::clone(&registry_client),
        Arc::clone(&health_status),
        state_reader_executor.clone(),
    );
    let dashboard_service =
        DashboardService::new_service(config.clone(), subnet_type, state_reader_executor.clone());
    let catchup_service = CatchUpPackageService::new_service(
        config.clone(),
        metrics.clone(),
        consensus_pool_cache.clone(),
    );

    let pprof_concurrency_buffer =
        GlobalConcurrencyLimitLayer::new(config.max_pprof_concurrent_requests);

    let pprof_home_service = PprofHomeService::new_service(pprof_concurrency_buffer.clone());
    let pprof_profile_service =
        PprofProfileService::new_service(pprof_collector.clone(), pprof_concurrency_buffer.clone());
    let pprof_flamegraph_service =
        PprofFlamegraphService::new_service(pprof_collector, pprof_concurrency_buffer);

    let health_status_refresher = HealthStatusRefreshLayer::new(
        log.clone(),
        metrics.clone(),
        Arc::clone(&health_status),
        consensus_pool_cache,
        state_reader_executor.clone(),
    );

    start_server_initialization(
        config.clone(),
        log.clone(),
        metrics.clone(),
        subnet_id,
        nns_subnet_id,
        registry_client.clone(),
        state_reader_executor,
        Arc::clone(&delegation_from_nns),
        Arc::clone(&health_status),
        rt_handle.clone(),
        tls_handshake.clone(),
    );

    let http_handler = HttpHandler {
        call_service,
        query_service,
        status_service,
        catchup_service,
        dashboard_service,
        canister_read_state_service,
        subnet_read_state_service,
        pprof_home_service,
        pprof_profile_service,
        pprof_flamegraph_service,
    };
    let main_service = create_main_service(
        metrics.clone(),
        config.clone(),
        http_handler,
        health_status_refresher,
    );

    let port_file_path = config.port_file_path.clone();
    // If addr == 0, then a random port will be assigned. In this case it
    // is useful to report the randomly assigned port by writing it to a file.
    let local_addr = tcp_listener.local_addr().unwrap();
    if let Some(path) = port_file_path {
        create_port_file(path, local_addr.port());
    }

    let metrics_cl = metrics.clone();
    let log_cl = log.clone();
    let conn_svc = ServiceBuilder::new().service_fn(move |tcp_stream: TcpStream| {
        handshake_and_serve_connection(
            log_cl.clone(),
            config.clone(),
            main_service.clone(),
            tcp_stream,
            tls_handshake.clone(),
            registry_client.clone(),
            metrics_cl.clone(),
        )
    });
    let conn_svc = BoxCloneService::new(conn_svc);
    rt_handle.clone().spawn(async move {
        loop {
            match tcp_listener.accept().await {
                Ok((tcp_stream, _)) => {
                    metrics.connections_total.inc();
                    // Start recording connection setup duration.
                    let mut conn_svc = conn_svc.clone();
                    tokio::spawn(async move {
                        let _ = conn_svc
                            .ready()
                            .await
                            .expect("The load shedder must always be ready.")
                            .call(tcp_stream)
                            .await;
                    });
                }
                Err(err) => {
                    // Don't exit the loop on a connection error. We will want to
                    // continue serving.
                    metrics
                        .connection_setup_duration
                        .with_label_values(&[STATUS_ERROR, ConnError::Io.into()])
                        .observe(0.0);

                    error!(log, "Can't accept TCP connection, error = {}", err);
                }
            }
        }
    });
}

fn create_main_service(
    metrics: HttpHandlerMetrics,
    config: Config,
    http_handler: HttpHandler,
    health_status_refresher: HealthStatusRefreshLayer,
) -> BoxCloneService<Request<Body>, Response<Body>, Infallible> {
    let route_service = service_fn(move |req: RequestWithTimer| {
        let http_handler = http_handler.clone();
        let config = config.clone();
        async move { Ok::<_, Infallible>(make_router(http_handler, config, req).await) }
    });

    BoxCloneService::new(
        ServiceBuilder::new()
            // Attach a timer as soon as we see a request.
            .map_request(move |request| {
                let _ = &metrics;
                // Start recording request duration.
                let request_timer = HistogramVecTimer::start_timer(
                    metrics.requests.clone(),
                    &REQUESTS_LABEL_NAMES,
                    [LABEL_UNKNOWN, LABEL_UNKNOWN],
                );
                (request, request_timer)
            })
            .layer(health_status_refresher)
            .service(route_service)
            .map_result(move |result| {
                let (response, request_timer) = result.expect("Can't panic on infallible");
                let status = response.status();
                // This is a workaround for `StatusCode::as_str()` not returning a `&'static
                // str`. It ensures `request_timer` is dropped before `status`.
                let mut timer = request_timer;
                timer.set_label(LABEL_STATUS, status.as_str());
                Ok::<_, Infallible>(response)
            }),
    )
}

async fn handshake_and_serve_connection(
    log: ReplicaLogger,
    config: Config,
    service: BoxCloneService<Request<Body>, Response<Body>, Infallible>,
    tcp_stream: TcpStream,
    tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    metrics: HttpHandlerMetrics,
) -> Result<(), Infallible> {
    let connection_start_time = Instant::now();
    let peer_addr = tcp_stream.peer_addr();
    let conn_after_handshake = stream_after_handshake(
        &log,
        config.connection_read_timeout_seconds,
        tcp_stream,
        tls_handshake,
        registry_client,
    )
    .await;

    let (connection_result, conn_type_label) = match conn_after_handshake {
        Err(err) => {
            warn!(
                log,
                "Handshake failed, error = {:?}, peer_addr = {:?}", err, peer_addr,
            );
            metrics
                .connection_setup_duration
                .with_label_values(&[STATUS_ERROR, err.into()])
                .observe(connection_start_time.elapsed().as_secs_f64());
            return Ok(());
        }
        Ok(conn_type) => {
            let conn_type_label = conn_type.to_string();
            metrics
                .connection_setup_duration
                .with_label_values(&[STATUS_SUCCESS, &conn_type_label])
                .observe(connection_start_time.elapsed().as_secs_f64());
            let conn_result = match conn_type {
                ConnType::Secure(tls_stream) => {
                    serve_connection_with_read_timeout(
                        tls_stream,
                        service,
                        config.connection_read_timeout_seconds,
                    )
                    .await
                }
                ConnType::Insecure(tcp_stream) => {
                    serve_connection_with_read_timeout(
                        tcp_stream,
                        service,
                        config.connection_read_timeout_seconds,
                    )
                    .await
                }
            };
            (conn_result, conn_type_label)
        }
    };
    match connection_result {
        Err(err) => {
            info!(
                log,
                "The connection was closed abruptly after {:?}, error = {}",
                connection_start_time.elapsed(),
                err
            );
            metrics
                .connection_duration
                .with_label_values(&[STATUS_ERROR, &conn_type_label])
                .observe(connection_start_time.elapsed().as_secs_f64())
        }
        Ok(()) => metrics
            .connection_duration
            .with_label_values(&[STATUS_SUCCESS, &conn_type_label])
            .observe(connection_start_time.elapsed().as_secs_f64()),
    }
    Ok(())
}

#[derive(Display)]
#[strum(serialize_all = "snake_case")]
enum ConnType {
    #[strum(serialize = "secure")]
    Secure(Box<dyn TlsStream>),
    #[strum(serialize = "insecure")]
    Insecure(TcpStream),
}

#[derive(IntoStaticStr, Debug)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum ConnError {
    #[strum(serialize = "tls_handshake")]
    TlsHandshake,
    Io,
    Timeout,
}

async fn stream_after_handshake(
    log: &ReplicaLogger,
    connection_read_timeout_seconds: u64,
    tcp_stream: TcpStream,
    tls_handshake: Arc<dyn TlsHandshake + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
) -> Result<ConnType, ConnError> {
    let mut b = [0_u8; 1];
    match timeout(
        Duration::from_secs(connection_read_timeout_seconds),
        tcp_stream.peek(&mut b),
    )
    .await
    {
        // The peek operation was successful within the timeout.
        Ok(Ok(_)) => {
            if b[0] == 22 {
                match tls_handshake
                    .perform_tls_server_handshake_without_client_auth(
                        tcp_stream,
                        registry_client.get_latest_version(),
                    )
                    .await
                {
                    Err(err) => {
                        warn!(log, "TLS handshaked failed with: {:?}", err);
                        Err(ConnError::TlsHandshake)
                    }
                    Ok(tls_stream) => Ok(ConnType::Secure(tls_stream)),
                }
            } else {
                Ok(ConnType::Insecure(tcp_stream))
            }
        }
        Ok(Err(err)) => {
            warn!(log, "Peeking TCP stream failed with: {:?}", err);
            Err(ConnError::Io)
        }
        Err(_) => Err(ConnError::Timeout),
    }
}

async fn serve_connection_with_read_timeout<T: AsyncRead + AsyncWrite + 'static>(
    stream: T,
    metrics_svc: BoxCloneService<Request<Body>, Response<Body>, Infallible>,
    connection_read_timeout_seconds: u64,
) -> Result<(), hyper::Error> {
    let http = Http::new();
    let mut stream = TimeoutStream::new(stream);
    stream.set_read_timeout(Some(Duration::from_secs(connection_read_timeout_seconds)));
    let stream = Box::pin(stream);
    http.serve_connection(stream, metrics_svc).await
}

type RequestWithTimer = (
    Request<Body>,
    HistogramVecTimer<'static, REQUESTS_NUM_LABELS>,
);
type ResponseWithTimer = (
    Response<Body>,
    HistogramVecTimer<'static, REQUESTS_NUM_LABELS>,
);

async fn make_router(
    http_handler: HttpHandler,
    config: Config,
    (mut req, mut timer): RequestWithTimer,
) -> ResponseWithTimer {
    let call_service = http_handler.call_service.clone();
    let query_service = http_handler.query_service.clone();
    let status_service = http_handler.status_service.clone();
    let catch_up_package_service = http_handler.catchup_service.clone();
    let dashboard_service = http_handler.dashboard_service.clone();
    let canister_read_state_service = http_handler.canister_read_state_service.clone();
    let subnet_read_state_service = http_handler.subnet_read_state_service.clone();
    let pprof_home_service = http_handler.pprof_home_service.clone();
    let pprof_profile_service = http_handler.pprof_profile_service.clone();
    let pprof_flamegraph_service = http_handler.pprof_flamegraph_service.clone();

    let svc = match req.method().clone() {
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
                timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::InvalidArgument.into());
                return (
                    make_plaintext_response(
                        StatusCode::BAD_REQUEST,
                        format!("Unexpected content-type, expected {}.", CONTENT_TYPE_CBOR),
                    ),
                    timer,
                );
            }

            // Check the path
            let path = req.uri().path();
            let (svc, effective_principal_id) =
                match *path.split('/').collect::<Vec<&str>>().as_slice() {
                    ["", "api", "v2", "canister", effective_canister_id, "call"] => {
                        timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::Call.into());
                        (
                            call_service,
                            Some(
                                PrincipalId::from_str(effective_canister_id)
                                    .map_err(|err| (effective_canister_id, err.to_string())),
                            ),
                        )
                    }
                    ["", "api", "v2", "canister", effective_canister_id, "query"] => {
                        timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::Query.into());
                        (
                            query_service,
                            Some(
                                PrincipalId::from_str(effective_canister_id)
                                    .map_err(|err| (effective_canister_id, err.to_string())),
                            ),
                        )
                    }
                    ["", "api", "v2", "canister", effective_canister_id, "read_state"] => {
                        timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::ReadState.into());
                        (
                            canister_read_state_service,
                            Some(
                                PrincipalId::from_str(effective_canister_id)
                                    .map_err(|err| (effective_canister_id, err.to_string())),
                            ),
                        )
                    }
                    ["", "api", "v2", "subnet", subnet_id, "read_state"] => {
                        timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::ReadState.into());
                        (
                            subnet_read_state_service,
                            Some(
                                PrincipalId::from_str(subnet_id)
                                    .map_err(|err| (subnet_id, err.to_string())),
                            ),
                        )
                    }
                    ["", "_", "catch_up_package"] => {
                        timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::CatchUpPackage.into());
                        (catch_up_package_service, None)
                    }
                    _ => {
                        timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::InvalidArgument.into());
                        return (
                            make_plaintext_response(
                                StatusCode::NOT_FOUND,
                                "Unexpected POST request path.".to_string(),
                            ),
                            timer,
                        );
                    }
                };

            // If url contains effective principal id we attach it to the request.
            if let Some(effective_principal_id) = effective_principal_id {
                match effective_principal_id {
                    Ok(id) => {
                        req.extensions_mut().insert(id);
                    }
                    Err((id, e)) => {
                        return (
                            make_plaintext_response(
                                StatusCode::BAD_REQUEST,
                                format!(
                                    "Malformed request: Invalid efffective principal id {}: {}",
                                    id, e
                                ),
                            ),
                            timer,
                        );
                    }
                }
            }
            svc
        }
        Method::GET => match req.uri().path() {
            "/api/v2/status" => {
                timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::Status.into());
                status_service
            }
            "/" | "/_/" => {
                timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::RedirectToDashboard.into());
                return (redirect_to_dashboard_response(), timer);
            }
            HTTP_DASHBOARD_URL_PATH => {
                timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::Dashboard.into());
                dashboard_service
            }
            "/_/pprof" => {
                timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::PprofHome.into());
                pprof_home_service
            }
            "/_/pprof/profile" => {
                timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::PprofProfile.into());
                pprof_profile_service
            }
            "/_/pprof/flamegraph" => {
                timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::PprofFlamegraph.into());
                pprof_flamegraph_service
            }
            "/_/threads" => {
                timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::Threads.into());
                return (threads::collect().await, timer);
            }
            _ => {
                timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::InvalidArgument.into());
                return (
                    make_plaintext_response(
                        StatusCode::NOT_FOUND,
                        "Unexpected GET request path.".to_string(),
                    ),
                    timer,
                );
            }
        },
        Method::OPTIONS => {
            timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::Options.into());
            return (no_content_response(), timer);
        }
        _ => {
            timer.set_label(LABEL_REQUEST_TYPE, ApiReqType::InvalidArgument.into());
            return (
                make_plaintext_response(
                    StatusCode::METHOD_NOT_ALLOWED,
                    format!(
                        "Unsupported method: {}. supported methods: POST, GET, OPTIONS.",
                        req.method()
                    ),
                ),
                timer,
            );
        }
    };
    let svc_per_conn = ServiceBuilder::new()
        .load_shed()
        .timeout(Duration::from_secs(config.request_timeout_seconds))
        .layer(BodyReceiverLayer::new(&config))
        .service(svc);
    (
        svc_per_conn
            .oneshot(req)
            .await
            .unwrap_or_else(map_box_error_to_response),
        timer,
    )
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
    tls_handshake: &(dyn TlsHandshake + Send + Sync),
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
            tls_handshake,
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
    tls_handshake: &(dyn TlsHandshake + Send + Sync),
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

    let tcp_stream: TcpStream = TcpStream::connect(addr)
        .await
        .map_err(|err| format!("Could not connect to node {}. {:?}.", addr, err))?;

    let tls_handshake = tls_handshake
        .perform_tls_client_handshake(tcp_stream, peer_id, registry_version)
        .await
        .map_err(|err| format!("TLS handshake failed: {:?}.", err))?;

    let (mut request_sender, connection) = hyper::client::conn::handshake(tls_handshake).await?;

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
        .body(Body::from(body))?;

    let raw_response_res = request_sender.send_request(nns_request).await?;

    let raw_response = receive_body(
        raw_response_res.into_body(),
        Duration::from_secs(config.max_request_receive_seconds),
        Byte::from_bytes(config.max_delegation_certificate_size_bytes.into()),
    )
    .await?;

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

fn no_content_response() -> Response<Body> {
    let mut response = Response::new(Body::from(""));
    *response.status_mut() = StatusCode::NO_CONTENT;
    *response.headers_mut() = get_cors_headers();
    response
}

fn redirect_to_dashboard_response() -> Response<Body> {
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

    // Verify that ReplicatedStateHealth is represented as an atomic by crossbeam.
    #[test]
    fn test_replica_state_atomic() {
        assert!(AtomicCell::<ReplicaHealthStatus>::is_lock_free());
    }
}
