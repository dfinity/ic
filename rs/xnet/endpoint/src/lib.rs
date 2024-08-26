#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod tests;

use axum::{body::Body, extract::State, response::IntoResponse, routing::any};
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::{rt::TokioIo, server::graceful::GracefulShutdown};
use ic_async_utils::start_tcp_listener;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_interfaces_certified_stream_store::{CertifiedStreamStore, EncodeStreamError};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{debug, info, warn, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry};
use ic_protobuf::messaging::xnet::v1 as pb;
use ic_protobuf::proxy::ProtoProxy;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_types::{xnet::StreamIndex, NodeId, PrincipalId, SubnetId};
use prometheus::{Histogram, HistogramVec};
use serde::Serialize;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use threadpool::ThreadPool;
use tokio::{
    runtime, select,
    sync::{oneshot, Notify},
};
use tower::Service;
use url::Url;

pub struct XNetEndpointMetrics {
    /// Records the time it took to serve an `/api/v1/stream` request, by
    /// resource and response status.
    pub request_duration: HistogramVec,
    /// Slice payload sizes.
    pub slice_payload_size: Histogram,
    /// Status 200 response size in bytes, by resource.
    pub response_size: HistogramVec,
}

const METRIC_REQUEST_DURATION: &str = "xnet_endpoint_request_duration_seconds";
const METRIC_SLICE_PAYLOAD_SIZE: &str = "xnet_endpoint_slice_payload_size_bytes";
const METRIC_RESPONSE_SIZE: &str = "xnet_endpoint_response_size_bytes";

const RESOURCE_ERROR: &str = "error";
const RESOURCE_STREAM: &str = "stream";
const RESOURCE_STREAMS: &str = "streams";
const RESOURCE_UNKNOWN: &str = "unknown";

const XNET_ENDPOINT_NUM_WORKER_THREADS: usize = 4;

impl XNetEndpointMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            request_duration: metrics_registry.histogram_vec(
                METRIC_REQUEST_DURATION,
                "The time it took to serve an API request, by resource and response status",
                // 0.1ms - 5s
                decimal_buckets(-4, 0),
                &["resource", "status"],
            ),
            slice_payload_size: metrics_registry.histogram(
                METRIC_SLICE_PAYLOAD_SIZE,
                "Slice payload sizes",
                // 10 B - 5 MB
                decimal_buckets(1, 6),
            ),
            response_size: metrics_registry.histogram_vec(
                METRIC_RESPONSE_SIZE,
                "Status 200 response size in bytes, by resource",
                // 10 B - 5 MB
                decimal_buckets(1, 6),
                &["resource"],
            ),
        }
    }
}

/// The messages processed by the background worker.
#[allow(clippy::large_enum_variant)]
enum WorkerMessage {
    /// Handle a request and send the result to the reply channel.
    HandleRequest {
        /// Incoming XNet HTTP request.
        request: Request<Body>,
        /// The channel that should be used to handle the reply to the user.
        response_sender: oneshot::Sender<Response<Body>>,
    },
    /// Stop processing requests.
    Stop,
}

/// HTTPS endpoint for fetching XNet stream slices.
///
/// Spawns a request handler thread, which holds a reference to the
/// `StateManager`; and an async task that runs the HTTPS server and accepts
/// incoming requests. The two are connected via a bounded `crossbeam::channel`,
/// also used for signaling shutdown on drop.
///
/// Exposed APIs:
/// * `/api/v1/streams`
///   - Produces a list of all `SubnetIds` with available streams.
/// * `/api/v1/stream/{SubnetId}[?msg_begin={StreamIndex}[&
///   witness_begin={StreamIndex}]][&msg_limit={usize}][&byte_limit={usize}]`
///   - Returns a stream slice for the given `SubnetId` with up to `msg_limit`
///     messages beginning at `msg_begin`, witness beginning at `witness_begin`
///     (`msg_begin` if missing), of up to `byte_limit` bytes.
pub struct XNetEndpoint {
    server_address: SocketAddr,
    handler_thread_pool: threadpool::ThreadPool,
    shutdown_notify: Arc<Notify>,
    request_sender: crossbeam_channel::Sender<WorkerMessage>,
    log: ReplicaLogger,
}

impl Drop for XNetEndpoint {
    /// Triggers shutdown by notifying the handler to close the channel
    /// receiver.
    fn drop(&mut self) {
        info!(self.log, "Shutting down XNet endpoint");

        // Request graceful shutdown of the HTTP server and the background thread.
        self.shutdown_notify.notify_one();

        for _ in 0..XNET_ENDPOINT_NUM_WORKER_THREADS {
            self.request_sender
                .send(WorkerMessage::Stop)
                .expect("failed to send stop signal!");
        }

        // Join the background workers.
        self.handler_thread_pool.join();

        info!(self.log, "XNet Endpoint shut down");
    }
}

const API_URL_STREAMS: &str = "/api/v1/streams";
const API_URL_STREAM_PREFIX: &str = "/api/v1/stream/";

/// Struct passed to each request handled by `enqueue_task`.
#[derive(Clone)]
struct Context {
    request_sender: crossbeam_channel::Sender<WorkerMessage>,
    metrics: Arc<XNetEndpointMetrics>,
}

fn ok<T>(t: T) -> Result<T, Infallible> {
    Ok(t)
}

/// Function that receives all requests made to the server. Each request is
/// transformed in a `WorkerMessage` and forwarded to a background worker for processing.
async fn enqueue_task(State(ctx): State<Context>, request: Request<Body>) -> impl IntoResponse {
    let (response_sender, response_receiver) = oneshot::channel();
    let task = WorkerMessage::HandleRequest {
        request,
        response_sender,
    };

    // NOTE: we must use non-blocking send here, otherwise we might
    // delay the event thread.
    if ctx.request_sender.try_send(task).is_err() {
        ctx.metrics
            .request_duration
            .with_label_values(&[RESOURCE_UNKNOWN, StatusCode::SERVICE_UNAVAILABLE.as_str()])
            .observe(0.0);

        return ok(Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Body::from("Queue full"))
            .unwrap());
    }

    ok(response_receiver
        .await
        .unwrap_or_else(|e| panic!("XNet Endpoint Handler shut down unexpectedly: {}", e)))
}

fn start_server(
    address: SocketAddr,
    ctx: Context,
    runtime_handle: runtime::Handle,
    tls: Arc<dyn TlsConfig + Send + Sync>,
    registry_client: Arc<dyn RegistryClient + Send + Sync>,
    log: ReplicaLogger,
    shutdown_notify: Arc<Notify>,
) -> SocketAddr {
    let _guard = runtime_handle.enter();

    // Create a router that handles all requests by calling `enqueue_task`
    // and attaches the `Context` as state.
    let router = any(enqueue_task).with_state(ctx);

    let hyper_service =
        hyper::service::service_fn(move |request: Request<Incoming>| router.clone().call(request));

    let http = hyper::server::conn::http1::Builder::new();

    let graceful_shutdown = GracefulShutdown::new();

    let listener = start_tcp_listener(address, &runtime_handle);
    let address = listener.local_addr().expect("Failed to get local addr.");

    let logger = log.clone();

    tokio::spawn(async move {
        loop {
            select! {
                Ok((stream, _peer_addr)) = listener.accept() => {
                    let logger = logger.clone();
                    let hyper_service = hyper_service.clone();

                    #[cfg(test)]
                    {
                        // TLS is not used in tests.
                        let _ = tls;
                        let _ = registry_client;

                        let io = TokioIo::new(stream);
                        let conn = http.serve_connection(io, hyper_service);
                        let wrapped = graceful_shutdown.watch(conn);
                        tokio::spawn(async move {
                            if let Err(err) = wrapped.await {
                                warn!(logger, "failed to serve connection: {err}");
                            }
                        });
                    }

                    #[cfg(not(test))]
                    {
                        // Creates a new TLS server config and uses it to accept the request.
                        let registry_version = registry_client.get_latest_version();
                        let server_config = match tls.server_config(
                            ic_crypto_tls_interfaces::SomeOrAllNodes::All,
                            registry_version,
                        ) {
                            Ok(config) => config,
                            Err(err) => {
                                warn!(logger, "Failed to get server config from crypto {err}");
                                return;
                            }
                        };

                        let tls_acceptor =
                            tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
                        match tls_acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                let io = TokioIo::new(tls_stream);
                                let conn = http.serve_connection(io, hyper_service);
                                let wrapped = graceful_shutdown.watch(conn);
                                tokio::spawn(async move {
                                    if let Err(err) = wrapped.await {
                                        warn!(logger, "failed to serve connection: {err}");
                                    }
                                });
                            }
                            Err(err) => {
                                warn!(logger, "Error setting up TLS stream: {err}");
                            }
                        };
                    }
                }
                _ = shutdown_notify.notified() => {
                    graceful_shutdown.shutdown().await;
                    break;
                }
            };
        }
    });

    address
}

impl XNetEndpoint {
    /// Creates and starts an `XNetEndpoint` to publish XNet `Streams`.
    pub fn new(
        runtime_handle: runtime::Handle,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        tls: Arc<dyn TlsConfig + Send + Sync>,
        registry_client: Arc<dyn RegistryClient + Send + Sync>,
        config: XNetEndpointConfig,
        metrics: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        let metrics = Arc::new(XNetEndpointMetrics::new(metrics));

        // The bounded channel for queuing requests between the HTTP server and the
        // background worker.
        //
        // We use a background worker because building streams is CPU and memory
        // bound and can take a few dozens of milliseconds, which is too long to execute
        // on the event handling thread.
        //
        // We do not use [tokio::runtime::Handle::spawn_blocking] because it's designed
        // for I/O bound tasks and can spawn extra threads when needed, which is
        // not the best strategy for CPU-bound tasks.
        //
        // We use a crossbeam channel instead of [tokio::sync::mpsc] because we want the
        // receiver to be blocking, and [tokio::sync::mpsc::Receiver::blocking_recv] is
        // only available in tokio ≥ 0.3.
        let (request_sender, request_receiver) =
            crossbeam_channel::bounded(XNET_ENDPOINT_NUM_WORKER_THREADS);

        let ctx = Context {
            metrics: Arc::clone(&metrics),
            request_sender: request_sender.clone(),
        };

        let shutdown_notify = Arc::new(Notify::new());

        let address = start_server(
            config.address,
            ctx,
            runtime_handle.clone(),
            tls,
            registry_client,
            log.clone(),
            shutdown_notify.clone(),
        );

        info!(log, "XNet Endpoint listening on {}", address);

        // Spawn a request handler. We pass the certified stream store, which is
        // currently realized by the state manager.
        let handler_log = log.clone();
        let base_url = Url::parse(&format!("http://{}/", address)).unwrap();
        let handler_thread_pool = ThreadPool::with_name(
            "XNet Endpoint Handler".to_string(),
            XNET_ENDPOINT_NUM_WORKER_THREADS,
        );
        for _ in 0..XNET_ENDPOINT_NUM_WORKER_THREADS {
            let request_receiver = request_receiver.clone();
            let base_url = base_url.clone();
            let handler_log = handler_log.clone();
            let metrics = Arc::clone(&metrics);
            let certified_stream_store = Arc::clone(&certified_stream_store);
            handler_thread_pool.execute(move || {
                while let Ok(WorkerMessage::HandleRequest {
                    request,
                    response_sender,
                }) = request_receiver.recv()
                {
                    let response = handle_http_request(
                        request,
                        certified_stream_store.as_ref(),
                        &base_url,
                        &metrics,
                        &handler_log,
                    );
                    response_sender.send(response).unwrap_or_else(|res| {
                        info!(
                            handler_log,
                            "Failed to respond with {:?}",
                            res.into_parts().0
                        )
                    });
                }
                debug!(handler_log, "  ...XNet Endpoint Handler shut down");
            });
        }

        Self {
            server_address: address,
            shutdown_notify,
            handler_thread_pool,
            request_sender,
            log,
        }
    }

    pub fn num_workers() -> usize {
        XNET_ENDPOINT_NUM_WORKER_THREADS
    }

    /// Returns the port that the HTTP server is listening on.
    #[allow(dead_code)]
    pub fn server_port(&self) -> u16 {
        self.server_address.port()
    }
}

/// Handles an incoming HTTP request by parsing the URL, handing over to
/// `route_request()` and replying with the produced response.
fn handle_http_request(
    request: Request<Body>,
    certified_stream_store: &dyn CertifiedStreamStore,
    base_url: &Url,
    metrics: &XNetEndpointMetrics,
    log: &ReplicaLogger,
) -> Response<Body> {
    match base_url.join(
        request
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(""),
    ) {
        Ok(url) => route_request(url, certified_stream_store, metrics),
        Err(e) => {
            let msg = format!("Invalid URL {}: {}", request.uri(), e);
            warn!(log, "{}", msg);
            bad_request(msg)
        }
    }
}

/// Routes an `XNetEndpoint` request to the appropriate handler; or produces an
/// HTTP 404 Not Found response if the URL doesn't match any handler.
fn route_request(
    url: Url,
    certified_stream_store: &dyn CertifiedStreamStore,
    metrics: &XNetEndpointMetrics,
) -> Response<Body> {
    let since = Instant::now();
    let mut resource = RESOURCE_ERROR;
    let response = match url.path() {
        API_URL_STREAMS => {
            resource = RESOURCE_STREAMS;
            handle_streams(certified_stream_store, metrics)
        }

        stream_url if stream_url.starts_with(API_URL_STREAM_PREFIX) => {
            resource = RESOURCE_STREAM;
            let subnet_id_str = &stream_url[API_URL_STREAM_PREFIX.len()..];
            let subnet_id = match PrincipalId::from_str(subnet_id_str) {
                Ok(subnet_id) => SubnetId::from(subnet_id),
                Err(_) => {
                    return bad_request(format!(
                        "Invalid subnet ID: {} in {}",
                        subnet_id_str, stream_url
                    ))
                }
            };

            let mut witness_begin = None;
            let mut msg_begin = None;
            let mut msg_limit = None;
            let mut byte_limit = None;
            for (param, value) in url.query_pairs() {
                let value = match value.parse::<u64>() {
                    Ok(v) => v,
                    Err(_) => {
                        return bad_request(format!("Invalid query param: {}", param));
                    }
                };
                match param.as_ref() {
                    "witness_begin" => witness_begin = Some(StreamIndex::new(value)),
                    "index" => msg_begin = Some(StreamIndex::new(value)),
                    "msg_begin" => msg_begin = Some(StreamIndex::new(value)),
                    "msg_limit" => msg_limit = Some(value as usize),
                    "byte_limit" => byte_limit = Some(value as usize),
                    _ => {
                        return bad_request(format!("Unexpected query param: {}", param));
                    }
                }
            }

            handle_stream(
                subnet_id,
                witness_begin,
                msg_begin,
                msg_limit,
                byte_limit,
                certified_stream_store,
                metrics,
            )
        }

        _ => not_found("Not Found"),
    };
    metrics
        .request_duration
        .with_label_values(&[resource, response.status().as_str()])
        .observe(since.elapsed().as_secs_f64());

    response
}

/// Returns a list of all subnets with available streams.
fn handle_streams(
    certified_stream_store: &dyn CertifiedStreamStore,
    metrics: &XNetEndpointMetrics,
) -> Response<Body> {
    let subnets: Vec<_> = certified_stream_store
        .subnets_with_certified_streams()
        .iter()
        .map(|subnet| subnet.to_string())
        .collect();
    observe_response_size(|| json_response(&subnets), RESOURCE_STREAMS, metrics)
}

/// Returns a stream slice for the given subnet; or a 404 response if a stream
/// for the respective subnet does not exist.
fn handle_stream(
    subnet_id: SubnetId,
    witness_begin: Option<StreamIndex>,
    msg_begin: Option<StreamIndex>,
    msg_limit: Option<usize>,
    byte_limit: Option<usize>,
    certified_stream_store: &dyn CertifiedStreamStore,
    metrics: &XNetEndpointMetrics,
) -> Response<Body> {
    let witness_begin = witness_begin.or(msg_begin);
    match certified_stream_store.encode_certified_stream_slice(
        subnet_id,
        witness_begin,
        msg_begin,
        msg_limit,
        byte_limit,
    ) {
        Ok(stream) => {
            metrics
                .slice_payload_size
                .observe(stream.payload.len() as f64);
            observe_response_size(
                || proto_response::<_, pb::CertifiedStreamSlice>(stream),
                RESOURCE_STREAM,
                metrics,
            )
        }
        Err(EncodeStreamError::NoStreamForSubnet(_)) => no_content(),
        Err(e @ EncodeStreamError::InvalidSliceBegin { .. }) => {
            range_not_satisfiable(e.to_string())
        }
        Err(e @ EncodeStreamError::InvalidSliceIndices { .. }) => bad_request(e.to_string()),
    }
}

/// Calls through to one of the `*_response` functions and observes the size of
/// the produced response.
fn observe_response_size<F>(f: F, resource: &str, metrics: &XNetEndpointMetrics) -> Response<Body>
where
    F: FnOnce() -> (Response<Body>, usize),
{
    let (response, size) = f();
    metrics
        .response_size
        .with_label_values(&[resource])
        .observe(size as f64);
    response
}

/// Serializes the response as JSON.
pub(crate) fn json_response<R: Serialize>(r: &R) -> (Response<Body>, usize) {
    let buf = serde_json::to_vec(r).expect("Could not serialize response");
    let size_bytes = buf.len();

    let response = Response::builder()
        .header("Content-Type", "application/json")
        .body(buf.into())
        .unwrap();

    (response, size_bytes)
}

/// Serializes the response as Protobuf.
pub(crate) fn proto_response<R, M>(r: R) -> (Response<Body>, usize)
where
    M: ProtoProxy<R>,
{
    let buf = M::proxy_encode(r);
    let size_bytes = buf.len();

    // Headers borrowed from Spring Framework -- https://bit.ly/32EDqoo -- and Google's Protobuf
    // reference -- https://bit.ly/35Q4yml. Might come in handy for e.g. a browser extension.
    let response = Response::builder()
        .header("Content-Type", "application/x-protobuf")
        .header("X-Protobuf-Schema", "certified_stream_slice.proto")
        .header("X-Protobuf-Message", "xnet.v1.CertifiedStreamSlice")
        .body(buf.into())
        .unwrap();

    (response, size_bytes)
}

/// Produces a 204 No Content response.
fn no_content() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .unwrap()
}

/// Produces a 400 Bad Request response with the given content.
fn bad_request<T: Into<Body>>(msg: T) -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(msg.into())
        .unwrap()
}

/// Produces a 404 Not Found response with the given content.
fn not_found<T: Into<Body>>(msg: T) -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(msg.into())
        .unwrap()
}

/// Produces a 416 Range Not Satisfiable response with the given content.
fn range_not_satisfiable<T: Into<Body>>(msg: T) -> Response<Body> {
    Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .body(msg.into())
        .unwrap()
}

/// The socket address for `XNetEndpoint` to listen on.
#[derive(Debug, PartialEq, Eq)]
pub struct XNetEndpointConfig {
    address: SocketAddr,
}

impl XNetEndpointConfig {
    /// Retrieves the `XNetEndpointConfig` for a given node from the latest
    /// available registry version.
    ///
    /// Logs an error message and returns the default value (`127.0.0.1:0`) if
    /// the `NodeRecord` registry entry does not exist; its `xnet` field is
    /// `None`; `xnet.ip_addr` is empty; or `xnet.port` is 0.
    ///
    /// # Panics
    ///
    /// Panics if registry reading fails or the IP address cannot be parsed.
    pub fn from(
        registry: Arc<dyn RegistryClient>,
        node_id: NodeId,
        log: &ReplicaLogger,
    ) -> XNetEndpointConfig {
        XNetEndpointConfig::try_from(registry, node_id)
            // If the node is not in the registry or has default values, return the default.
            .unwrap_or_else(|| {
                info!(log, "No XNet configuration for node {}. This is an error in production, but may be ignored in single-subnet test deployments.", node_id);
                Default::default()
            })
    }

    fn try_from(registry: Arc<dyn RegistryClient>, node_id: NodeId) -> Option<XNetEndpointConfig> {
        let version = registry.get_latest_version();
        let node_record = registry
            .get_node_record(node_id, version)
            .unwrap_or_else(|e| {
                panic!(
                    "Could not retrieve registry record for node {}: {}",
                    node_id, e
                )
            })?;

        let endpoint = node_record.xnet?;

        // Return None if fields have default values.
        if endpoint.port == 0 || endpoint.ip_addr.is_empty() {
            return None;
        }

        let address: SocketAddr = SocketAddr::new(
            endpoint.ip_addr.parse().unwrap(),
            u16::try_from(endpoint.port).unwrap(),
        );

        Some(XNetEndpointConfig { address })
    }
}

impl Default for XNetEndpointConfig {
    /// By default listen on 127.0.0.1, on a free port assigned by the OS.
    fn default() -> XNetEndpointConfig {
        XNetEndpointConfig {
            address: SocketAddr::from(([127, 0, 0, 1], 0)),
        }
    }
}
