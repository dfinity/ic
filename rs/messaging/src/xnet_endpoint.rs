#[cfg(test)]
mod config_tests;
#[cfg(test)]
mod tests;

use hyper::{Body, Request, Response, StatusCode};
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces::{
    certified_stream_store::{CertifiedStreamStore, EncodeStreamError},
    registry::RegistryClient,
};
use ic_logger::{debug, info, warn, ReplicaLogger};
use ic_metrics::{buckets::decimal_buckets, MetricsRegistry, Timer};
use ic_protobuf::messaging::xnet::v1 as pb;
use ic_protobuf::proxy::ProtoProxy;
use ic_registry_client::helper::node::NodeRegistry;
use ic_types::{
    registry::connection_endpoint::ConnectionEndpoint, xnet::StreamIndex, NodeId, PrincipalId,
    SubnetId,
};
use prometheus::{Histogram, HistogramVec};
use serde::Serialize;
use std::convert::{Infallible, TryFrom};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::{
    runtime,
    sync::{oneshot, Notify},
};
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
    handler_thread_handle: Option<std::thread::JoinHandle<()>>,
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
        self.shutdown_notify.notify();
        self.request_sender
            .send(WorkerMessage::Stop)
            .expect("failed to send stop signal");

        // Join the background worker.
        if let Some(h) = self.handler_thread_handle.take() {
            h.join().expect("could not join handler thread");
        }

        info!(self.log, "XNet Endpoint shut down");
    }
}

const API_URL_STREAMS: &str = "/api/v1/streams";
const API_URL_STREAM_PREFIX: &str = "/api/v1/stream/";

/// We should not buffer too many requests. The handler is single-threaded and
/// (initially) block making is synchronous. Also, the longer the queue, the
/// longer it may take to shut down.
const REQUEST_QUEUE_LENGTH: usize = 3;

impl<'a> XNetEndpoint {
    /// Creates and starts an `XNetEndpoint` to publish XNet `Streams`.
    pub fn new(
        runtime_handle: runtime::Handle,
        certified_stream_store: Arc<dyn CertifiedStreamStore>,
        tls: Arc<dyn TlsHandshake + Send + Sync>,
        registry_client: Arc<dyn RegistryClient + Send + Sync>,
        config: XNetEndpointConfig,
        metrics: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        use crate::hyper::{tls_bind, ExecuteOnRuntime, TlsConnection};
        use hyper::service::{make_service_fn, service_fn};

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
        let (request_sender, request_receiver) = crossbeam_channel::bounded(REQUEST_QUEUE_LENGTH);

        let make_service = make_service_fn({
            #[derive(Clone)]
            struct Context {
                log: ReplicaLogger,
                request_sender: crossbeam_channel::Sender<WorkerMessage>,
                metrics: Arc<XNetEndpointMetrics>,
            }

            let ctx = Context {
                log: log.clone(),
                metrics: Arc::clone(&metrics),
                request_sender: request_sender.clone(),
            };

            fn ok<T>(t: T) -> Result<T, Infallible> {
                Ok(t)
            }

            move |tls_conn: &TlsConnection| {
                let ctx = ctx.clone();
                debug!(
                    ctx.log,
                    "Serving XNet streams to peer {:?}",
                    tls_conn.peer()
                );

                async move {
                    let ctx = ctx.clone();
                    ok(service_fn({
                        move |request: Request<Body>| {
                            let ctx = ctx.clone();

                            async move {
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
                                        .with_label_values(&[
                                            RESOURCE_UNKNOWN,
                                            StatusCode::SERVICE_UNAVAILABLE.as_str(),
                                        ])
                                        .observe(0.0);

                                    return ok(Response::builder()
                                        .status(StatusCode::SERVICE_UNAVAILABLE)
                                        .body(Body::from("Queue full"))
                                        .unwrap());
                                }

                                ok(response_receiver.await.unwrap_or_else(|e| {
                                    panic!("XNet Endpoint Handler shut down unexpectedly: {}", e)
                                }))
                            }
                        }
                    }))
                }
            }
        });

        let (address, server) = runtime_handle.enter(|| {
            let (addr, builder) =
                tls_bind(&config.address, tls, registry_client).unwrap_or_else(|e| {
                    panic!(
                        "failed to bind XNet socket, address {:?}: {}",
                        config.address, e
                    )
                });
            (
                addr,
                builder
                    .executor(ExecuteOnRuntime(runtime_handle.clone()))
                    .serve(make_service),
            )
        });

        info!(log, "XNet Endpoint listening on {}", address);

        let shutdown_notify = Arc::new(Notify::new());

        let shutdown = server.with_graceful_shutdown({
            let shutdown_notify = Arc::clone(&shutdown_notify);
            async move { shutdown_notify.notified().await }
        });

        runtime_handle.spawn({
            let log = log.clone();
            async move {
                if let Err(e) = shutdown.await {
                    warn!(log, "XNet http server failed: {}", e);
                }
            }
        });

        // Spawn a request handler. We pass the certified stream store, which is
        // currently realized by the state manager.
        let handler_log = log.clone();
        let base_url = Url::parse(&format!("http://{}/", address)).unwrap();

        let handler_thread_handle = std::thread::Builder::new()
            .name("XNet Endpoint Handler".to_string())
            .spawn(move || {
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
            })
            .expect("Cannot spawn XNet Endpoint Handler thread");

        Self {
            server_address: address,
            shutdown_notify,
            request_sender,
            handler_thread_handle: Some(handler_thread_handle),
            log,
        }
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
    let timer = Timer::start();
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
        .observe(timer.elapsed());

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
        Err(e @ EncodeStreamError::InvalidSliceBegin { .. })
        | Err(e @ EncodeStreamError::InvalidSliceIndices { .. }) => bad_request(e.to_string()),
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
    let buf = M::proxy_encode(r).expect("Could not serialize response");
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
            .get_transport_info(node_id, version)
            .unwrap_or_else(|e| {
                panic!(
                    "Could not retrieve registry record for node {}: {}",
                    node_id, e
                )
            })?;

        // TODO(OR4-18): Correctly handle multiple endpoints
        // Prefer the first item from xnet_api if it exists, otherwise use the
        // the only entry in xnet.
        let endpoint = if node_record.xnet_api.is_empty() {
            node_record.xnet?
        } else {
            node_record.xnet_api[0].clone()
        };

        // Return None if fields have default values.
        if endpoint.port == 0 || endpoint.ip_addr.is_empty() {
            return None;
        }

        let endpoint = ConnectionEndpoint::try_from(endpoint.clone())
            .unwrap_or_else(|e| panic!("Node {} XNet endpoint [{:?}]: {}", node_id, endpoint, e));

        let address = SocketAddr::from(&endpoint);

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
