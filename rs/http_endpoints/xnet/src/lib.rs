#[cfg(test)]
mod tests;

use axum::body::Body;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{MethodRouter, any};
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_util::{rt::TokioIo, server::graceful::GracefulShutdown};
use ic_config::message_routing::Config;
use ic_crypto_tls_interfaces::TlsConfig;
use ic_http_endpoints_async_utils::start_tcp_listener;
use ic_interfaces_certified_stream_store::{CertifiedStreamStore, EncodeStreamError};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, info, warn};
use ic_metrics::{MetricsRegistry, buckets::decimal_buckets};
use ic_protobuf::messaging::xnet::v1 as pb;
use ic_protobuf::proxy::ProtoProxy;
use ic_registry_client_helpers::subnet::{SubnetRegistry, get_node_ids_from_subnet_record};
use ic_types::{NodeId, PrincipalId, SubnetId, xnet::StreamIndex};
use prometheus::{Histogram, HistogramVec, IntCounter};
use serde::Serialize;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Notify, Semaphore};
use tokio::{runtime, select};
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
    pub connections_total: IntCounter,
    pub closed_connections_total: IntCounter,
}

const METRIC_REQUEST_DURATION: &str = "xnet_endpoint_request_duration_seconds";
const METRIC_SLICE_PAYLOAD_SIZE: &str = "xnet_endpoint_slice_payload_size_bytes";
const METRIC_RESPONSE_SIZE: &str = "xnet_endpoint_response_size_bytes";
const METRIC_CONNECTIONS: &str = "xnet_endpoint_connections_total";
const METRIC_CLOSED_CONNECTIONS: &str = "xnet_endpoint_closed_connections_total";

const RESOURCE_ERROR: &str = "error";
const RESOURCE_STREAM: &str = "stream";
const RESOURCE_STREAMS: &str = "streams";
const RESOURCE_UNKNOWN: &str = "unknown";

const XNET_ENDPOINT_MAX_CONCURRENT_REQUESTS: usize = 4;

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
            connections_total: metrics_registry.int_counter(
                METRIC_CONNECTIONS,
                "Total number of accepted XNet TCP connections.",
            ),
            closed_connections_total: metrics_registry.int_counter(
                METRIC_CLOSED_CONNECTIONS,
                "Total number of XNet connections dropped due to errors.",
            ),
        }
    }
}

/// HTTPS endpoint for fetching XNet stream slices.
///
/// Exposed APIs:
/// * `/api/v1/streams`
///   - Produces a list of all `SubnetIds` with available streams.
/// * `/api/v1/stream/{SubnetId}[?msg_begin={StreamIndex}[&
///   witness_begin={StreamIndex}]][&msg_limit={usize}][&byte_limit={usize}]`
///   - Returns a stream slice for the given `SubnetId` with up to `msg_limit`
///     messages beginning at `msg_begin`, witness beginning at `witness_begin`
///     (`msg_begin` if missing), of up to `byte_limit` bytes.
///   - Only served to nodes of `SubnetId`, i.e. a node may only fetch the
///     stream addressed to its own subnet.
///
/// Connections are mutually authenticated TLS, so every caller is a registered
/// node whose `NodeId` the handlers can rely on (see `serve_connection()`).
pub struct XNetEndpoint {
    server_address: SocketAddr,
    shutdown_notify: Arc<Notify>,
    log: ReplicaLogger,
}

impl Drop for XNetEndpoint {
    /// Triggers shutdown by notifying the handler to close the channel
    /// receiver.
    fn drop(&mut self) {
        info!(self.log, "Shutting down XNet endpoint");

        // Request graceful shutdown of the HTTP server and the background thread.
        self.shutdown_notify.notify_one();

        info!(self.log, "XNet Endpoint shut down");
    }
}

const API_URL_STREAMS: &str = "/api/v1/streams";
const API_URL_STREAM_PREFIX: &str = "/api/v1/stream/";

/// Struct passed to each request handled by `handle_xnet_request`.
struct Context<CertifiedStreamStore_: CertifiedStreamStore + 'static> {
    log: ReplicaLogger,
    semaphore: Arc<Semaphore>,
    metrics: Arc<XNetEndpointMetrics>,
    certified_stream_store: Arc<CertifiedStreamStore_>,
    registry_client: Arc<dyn RegistryClient>,
    base_url: Url,
}

fn ok<T>(t: T) -> Result<T, Infallible> {
    Ok(t)
}

/// Handles an incoming HTTP request by taking a permit from the semaphore, parsing the URL,
/// handing over to `route_request()` and replying with the produced response.
async fn handle_xnet_request(
    State(ctx): State<Arc<Context<impl CertifiedStreamStore>>>,
    request: Request<Body>,
) -> impl IntoResponse {
    let owned_permit = match ctx.semaphore.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            ctx.metrics
                .request_duration
                .with_label_values(&[RESOURCE_UNKNOWN, StatusCode::SERVICE_UNAVAILABLE.as_str()])
                .observe(0.0);

            return ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("Queue full"))
                .unwrap());
        }
    };
    let peer_node_id = request.extensions().get::<NodeId>().copied();

    ok(tokio::task::spawn_blocking(move || {
        let _permit = owned_permit;

        match ctx.base_url.join(
            request
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or(""),
        ) {
            Ok(url) => route_request(url, peer_node_id, &ctx),
            Err(e) => {
                let msg = format!("Invalid URL {}: {}", request.uri(), e);
                warn!(ctx.log, "{}", msg);
                bad_request(msg)
            }
        }
    })
    .await
    .expect("Processing http request panicked!"))
}

fn start_server(
    address: SocketAddr,
    metrics: Arc<XNetEndpointMetrics>,
    certified_stream_store: Arc<impl CertifiedStreamStore + 'static>,
    runtime_handle: runtime::Handle,
    tls: Arc<impl TlsConfig + 'static>,
    registry_client: Arc<impl RegistryClient + 'static>,
    log: ReplicaLogger,
    shutdown_notify: Arc<Notify>,
) -> SocketAddr {
    let _guard = runtime_handle.enter();

    let listener = start_tcp_listener(address, &runtime_handle);
    let address = listener.local_addr().expect("Failed to get local addr.");

    let ctx = Arc::new(Context {
        log: log.clone(),
        metrics: Arc::clone(&metrics),
        semaphore: Arc::new(Semaphore::new(XNET_ENDPOINT_MAX_CONCURRENT_REQUESTS)),
        certified_stream_store,
        registry_client: registry_client.clone(),
        base_url: Url::parse(&format!("http://{address}/")).unwrap(),
    });

    // Create a router that handles all requests by calling `handle_xnet_request`
    // and attaches the `Context` as state.
    let router = any(handle_xnet_request).with_state(ctx);

    let graceful_shutdown = GracefulShutdown::new();

    tokio::spawn(async move {
        loop {
            select! {
                Ok((stream, _peer_addr)) = listener.accept() => {
                    let metrics = metrics.clone();
                    metrics.connections_total.inc();
                    let logger = log.clone();
                    let router = router.clone();
                    let registry_client = registry_client.clone();
                    let tls = tls.clone();
                    tokio::spawn(async move {
                        #[cfg(test)]
                        {
                            // TLS is not used in tests.
                            let _ = tls;
                            let _ = registry_client;

                            let io = TokioIo::new(stream);
                            if let Err(err) = serve_connection(io, router, None).await {
                                warn!(logger, "failed to serve connection: {err}");
                            }
                        }

                        #[cfg(not(test))]
                        {
                            // Creates a new TLS server config and uses it to accept the request.
                            let registry_version = registry_client.get_latest_version();
                            let mut server_config = match tls.server_config(
                                ic_crypto_tls_interfaces::SomeOrAllNodes::All,
                                registry_version,
                            ) {
                                Ok(config) => config,
                                Err(err) => {
                                    warn!(logger, "Failed to get server config from crypto {err}");
                                    return;
                                }
                            };

                            const ALPN_HTTP2: &[u8; 2] = b"h2";
                            const ALPN_HTTP1_1: &[u8; 8] = b"http/1.1";
                            server_config.alpn_protocols = vec![ALPN_HTTP2.to_vec(), ALPN_HTTP1_1.to_vec()];

                            let tls_acceptor =
                                tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
                            match tls_acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    let peer_node_id = match peer_node_id(&tls_stream) {
                                        Ok(peer_node_id) => peer_node_id,

                                        // Unreachable: peer was authenticated, so it must have a NodeId.
                                        Err(err) => {
                                            ic_logger::error!(logger, "Rejecting connection: {err}");
                                            metrics.closed_connections_total.inc();
                                            return;
                                        }
                                    };

                                    let io = TokioIo::new(tls_stream);
                                    if let Err(err) = serve_connection(io, router, Some(peer_node_id)).await {
                                        warn!(logger, "failed to serve connection: {err}");
                                        metrics.closed_connections_total.inc();
                                    }
                                }
                                Err(err) => {
                                    warn!(logger, "Error setting up TLS stream: {err}");
                                    metrics.closed_connections_total.inc();

                                }
                            };
                        }
                    });
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

/// Serves an accepted connection, tagging every request on it with the
/// authenticated peer `NodeId`, so handlers can attribute it.
async fn serve_connection<Io>(
    io: Io,
    router: MethodRouter<()>,
    peer_node_id: Option<NodeId>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    Io: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
        if let Some(peer_node_id) = peer_node_id {
            request.extensions_mut().insert(peer_node_id);
        }
        router.clone().call(request)
    });

    hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, service)
        .await
}

/// Extracts the peer's `NodeId` from its TLS client certificate.
///
/// The TLS handshake has already verified that the peer is a registered node,
/// so this only decodes the already authenticated identity.
#[cfg(not(test))]
fn peer_node_id<Io>(tls_stream: &tokio_rustls::server::TlsStream<Io>) -> Result<NodeId, String> {
    let certificates = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .ok_or("peer presented no TLS certificate")?;
    let [certificate] = certificates else {
        return Err(format!(
            "expected a single peer TLS certificate, got {}",
            certificates.len()
        ));
    };

    ic_crypto_utils_tls::node_id_from_certificate_der(certificate.as_ref())
        .map_err(|err| format!("invalid peer TLS certificate: {err}"))
}

impl XNetEndpoint {
    /// Creates and starts an `XNetEndpoint` to publish XNet `Streams`.
    pub fn new(
        runtime_handle: runtime::Handle,
        certified_stream_store: Arc<impl CertifiedStreamStore + 'static>,
        tls: Arc<impl TlsConfig + 'static>,
        registry_client: Arc<impl RegistryClient + 'static>,
        config: Config,
        metrics: &MetricsRegistry,
        log: ReplicaLogger,
    ) -> Self {
        let metrics = Arc::new(XNetEndpointMetrics::new(metrics));

        let shutdown_notify = Arc::new(Notify::new());
        let localhost_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let addr = match config.xnet_ip_addr.parse() {
            Ok(ip_addr) => SocketAddr::new(ip_addr, config.xnet_port),
            Err(_) => localhost_v4,
        };
        let address = start_server(
            addr,
            metrics,
            certified_stream_store,
            runtime_handle.clone(),
            tls,
            registry_client,
            log.clone(),
            shutdown_notify.clone(),
        );

        info!(log, "XNet Endpoint listening on {}", address);

        Self {
            server_address: address,
            shutdown_notify,
            log,
        }
    }

    pub fn num_workers() -> usize {
        XNET_ENDPOINT_MAX_CONCURRENT_REQUESTS
    }

    /// Returns the port that the HTTP server is listening on.
    #[allow(dead_code)]
    pub fn server_port(&self) -> u16 {
        self.server_address.port()
    }
}

/// Routes an `XNetEndpoint` request to the appropriate handler; or produces an
/// HTTP 404 Not Found response if the URL doesn't match any handler.
fn route_request(
    url: Url,
    peer_node_id: Option<NodeId>,
    ctx: &Context<impl CertifiedStreamStore>,
) -> Response<Body> {
    let since = Instant::now();
    let (resource, response) = route_request_impl(url, peer_node_id, ctx);
    ctx.metrics
        .request_duration
        .with_label_values(&[resource, response.status().as_str()])
        .observe(since.elapsed().as_secs_f64());

    response
}

/// Implementation of `route_request()`, for easy instrumentation.
fn route_request_impl(
    url: Url,
    peer_node_id: Option<NodeId>,
    ctx: &Context<impl CertifiedStreamStore>,
) -> (&'static str, Response<Body>) {
    match url.path() {
        API_URL_STREAMS => (RESOURCE_STREAMS, handle_streams(ctx)),

        stream_url if stream_url.starts_with(API_URL_STREAM_PREFIX) => {
            let subnet_id_str = &stream_url[API_URL_STREAM_PREFIX.len()..];
            let subnet_id = match PrincipalId::from_str(subnet_id_str) {
                Ok(subnet_id) => SubnetId::from(subnet_id),
                Err(_) => {
                    return (
                        RESOURCE_STREAM,
                        bad_request(format!(
                            "Invalid subnet ID: {subnet_id_str} in {stream_url}"
                        )),
                    );
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
                        return (
                            RESOURCE_STREAM,
                            bad_request(format!("Invalid query param: {param}")),
                        );
                    }
                };
                match param.as_ref() {
                    "witness_begin" => witness_begin = Some(StreamIndex::new(value)),
                    "index" => msg_begin = Some(StreamIndex::new(value)),
                    "msg_begin" => msg_begin = Some(StreamIndex::new(value)),
                    "msg_limit" => msg_limit = Some(value as usize),
                    "byte_limit" => byte_limit = Some(value as usize),
                    _ => {
                        return (
                            RESOURCE_STREAM,
                            bad_request(format!("Unexpected query param: {param}")),
                        );
                    }
                }
            }

            (
                RESOURCE_STREAM,
                handle_stream(
                    subnet_id,
                    witness_begin,
                    msg_begin,
                    msg_limit,
                    byte_limit,
                    peer_node_id,
                    ctx,
                ),
            )
        }

        _ => (RESOURCE_ERROR, not_found("Not Found")),
    }
}

/// Returns a list of all subnets with available streams.
fn handle_streams(ctx: &Context<impl CertifiedStreamStore>) -> Response<Body> {
    let subnets: Vec<_> = ctx
        .certified_stream_store
        .subnets_with_certified_streams()
        .iter()
        .map(|subnet| subnet.to_string())
        .collect();
    observe_response_size(|| json_response(&subnets), RESOURCE_STREAMS, &ctx.metrics)
}

/// Returns a stream slice for the given subnet; a 403 response if the caller is
/// not a node of that subnet; or a 204 response if a stream for the respective
/// subnet does not exist.
fn handle_stream(
    subnet_id: SubnetId,
    witness_begin: Option<StreamIndex>,
    msg_begin: Option<StreamIndex>,
    msg_limit: Option<usize>,
    byte_limit: Option<usize>,
    peer_node_id: Option<NodeId>,
    ctx: &Context<impl CertifiedStreamStore>,
) -> Response<Body> {
    // `peer_node_id` is only `None` in tests. In production, the TLS handshake
    // always verifies that the caller is a registered node.
    if let Some(node_id) = peer_node_id
        && let Err(reason) =
            check_subnet_membership(node_id, subnet_id, ctx.registry_client.as_ref())
    {
        let msg = format!("Node {node_id} may not fetch the stream to {subnet_id}: {reason}");
        warn!(ctx.log, "{}", msg);
        return forbidden(msg);
    }

    let witness_begin = witness_begin.or(msg_begin);
    match ctx.certified_stream_store.encode_certified_stream_slice(
        subnet_id,
        witness_begin,
        msg_begin,
        msg_limit,
        byte_limit,
    ) {
        Ok(stream) => {
            ctx.metrics
                .slice_payload_size
                .observe(stream.payload.len() as f64);
            observe_response_size(
                || proto_response::<_, pb::CertifiedStreamSlice>(stream),
                RESOURCE_STREAM,
                &ctx.metrics,
            )
        }
        Err(EncodeStreamError::NoStreamForSubnet(_)) => no_content(),
        Err(e @ EncodeStreamError::InvalidSliceBegin { .. }) => {
            range_not_satisfiable(e.to_string())
        }
        Err(e @ EncodeStreamError::InvalidSliceIndices { .. }) => bad_request(e.to_string()),
    }
}

/// Checks that `node_id` is a member of `subnet_id` at the latest registry
/// version. If not a member or if the registry read fails, returns an error.
fn check_subnet_membership(
    node_id: NodeId,
    subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
) -> Result<(), String> {
    let registry_version = registry_client.get_latest_version();
    let subnet_record = registry_client
        .get_subnet_record(subnet_id, registry_version)
        .map_err(|err| format!("failed to read subnet record: {err}"))?
        .ok_or_else(|| format!("no subnet record at registry version {registry_version}"))?;
    let members = get_node_ids_from_subnet_record(&subnet_record)
        .map_err(|err| format!("failed to decode subnet membership: {err}"))?;

    if members.contains(&node_id) {
        Ok(())
    } else {
        Err(format!(
            "not a member at registry version {registry_version}"
        ))
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

/// Produces a 403 Forbidden response with the given content.
fn forbidden<T: Into<Body>>(msg: T) -> Response<Body> {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
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
