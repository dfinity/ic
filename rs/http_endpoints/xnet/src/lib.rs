#[cfg(test)]
mod tests;

use axum::body::{Body, HttpBody};
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{MethodRouter, any};
use bytes::Bytes;
use http_body_util::LengthLimitError;
use hyper::{Method, Request, Response, StatusCode, body::Incoming};
use hyper_util::{rt::TokioIo, server::graceful::GracefulShutdown};
use ic_config::message_routing::{ADVERT_MAX_BODY_BYTES, Config};
use ic_crypto_tls_interfaces::TlsConfig;
use ic_http_endpoints_async_utils::start_tcp_listener;
use ic_interfaces::messaging::{XNetAdvertError, XNetAdvertHandler, XNetAdvertOutcome};
use ic_interfaces_certified_stream_store::{CertifiedStreamStore, EncodeStreamError};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, info, warn};
use ic_metrics::{MetricsRegistry, buckets::decimal_buckets};
use ic_protobuf::messaging::xnet::v1 as pb;
use ic_protobuf::proxy::ProtoProxy;
use ic_registry_client_helpers::subnet::{SubnetRegistry, get_node_ids_from_subnet_record};
use ic_types::{NodeId, PrincipalId, SubnetId, xnet::StreamIndex};
use prometheus::{Histogram, HistogramVec, IntCounter, IntCounterVec};
use serde::Serialize;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
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
    /// Adverts received, by status.
    pub adverts: IntCounterVec,
    /// Adverts whose certification failed to verify, by remote subnet. A node that
    /// persistently sends such adverts is misbehaving (brief stretches following
    /// the change of a subnet's public key are expected).
    pub advert_verification_failures: IntCounterVec,
}

const METRIC_REQUEST_DURATION: &str = "xnet_endpoint_request_duration_seconds";
const METRIC_SLICE_PAYLOAD_SIZE: &str = "xnet_endpoint_slice_payload_size_bytes";
const METRIC_RESPONSE_SIZE: &str = "xnet_endpoint_response_size_bytes";
const METRIC_CONNECTIONS: &str = "xnet_endpoint_connections_total";
const METRIC_CLOSED_CONNECTIONS: &str = "xnet_endpoint_closed_connections_total";
const METRIC_ADVERTS: &str = "xnet_endpoint_adverts_total";
const METRIC_ADVERT_VERIFICATION_FAILURES: &str =
    "xnet_endpoint_advert_verification_failures_total";

const RESOURCE_ADVERT: &str = "advert";
const RESOURCE_ERROR: &str = "error";
const RESOURCE_STREAM: &str = "stream";
const RESOURCE_STREAMS: &str = "streams";
const RESOURCE_UNKNOWN: &str = "unknown";

const XNET_ENDPOINT_MAX_CONCURRENT_REQUESTS: usize = 4;

/// Adverts accepted from any one node per second, sustained. A node advertises
/// at most once per certified height of its subnet, i.e. at most 2.5 times a
/// second, and only to a fraction of our nodes.
const ADVERT_RATE_LIMIT_PER_SECOND: f64 = 5.0;
/// Adverts accepted from any one node in a burst.
const ADVERT_RATE_LIMIT_BURST: f64 = 10.0;
/// Number of nodes above which the rate limiter drops the buckets that have
/// refilled completely, as they are equivalent to absent ones.
const ADVERT_RATE_LIMIT_MAX_BUCKETS: usize = 1024;

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
                // 10 B - 50 MB
                decimal_buckets(1, 7),
            ),
            response_size: metrics_registry.histogram_vec(
                METRIC_RESPONSE_SIZE,
                "Status 200 response size in bytes, by resource",
                // 10 B - 50 MB
                decimal_buckets(1, 7),
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
            adverts: metrics_registry.int_counter_vec(
                METRIC_ADVERTS,
                "Adverts received, by status.",
                &["status"],
            ),
            advert_verification_failures: metrics_registry.int_counter_vec(
                METRIC_ADVERT_VERIFICATION_FAILURES,
                "Adverts whose certification failed to verify, by remote subnet.",
                &["remote"],
            ),
        }
    }
}

/// HTTPS endpoint for fetching XNet stream slices.
///
/// Exposed APIs:
/// * `/api/v1/streams`
///   - Produces a list of all `SubnetIds` with available streams.
/// * `POST /api/v1/advert/{SubnetId}`
///   - Accepts a certified stream header (as a header-only
///     `CertifiedStreamSlice`) from a node of `SubnetId`, telling us that it
///     holds something we may not have seen.
///   - Replies with our own certified header for `SubnetId` iff the advert
///     brought nothing new.
/// * `/api/v1/stream/{SubnetId}[?msg_begin={StreamIndex}[&witness_begin={StreamIndex}]][&msg_limit={usize}][&byte_limit={usize}]`
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
const API_URL_ADVERT_PREFIX: &str = "/api/v1/advert/";

/// Struct passed to each request handled by `handle_xnet_request`.
struct Context<CertifiedStreamStore_: CertifiedStreamStore + 'static> {
    semaphore: Arc<Semaphore>,
    certified_stream_store: Arc<CertifiedStreamStore_>,
    advert_handler: Arc<dyn XNetAdvertHandler>,
    registry_client: Arc<dyn RegistryClient>,
    advert_rate_limiter: AdvertRateLimiter,
    base_url: Url,
    metrics: Arc<XNetEndpointMetrics>,
    log: ReplicaLogger,
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

    // Only the advert endpoint takes a request body.
    let is_advert =
        request.method() == Method::POST && request.uri().path().starts_with(API_URL_ADVERT_PREFIX);
    let (parts, body) = request.into_parts();
    let body = if is_advert {
        axum::body::to_bytes(body, ADVERT_MAX_BODY_BYTES).await
    } else {
        Ok(Bytes::new())
    };

    ok(tokio::task::spawn_blocking(move || {
        let _permit = owned_permit;

        match ctx.base_url.join(
            parts
                .uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or(""),
        ) {
            Ok(url) => route_request(url, parts.method, body, peer_node_id, &ctx),
            Err(e) => {
                let msg = format!("Invalid URL {}: {}", parts.uri, e);
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
    certified_stream_store: Arc<impl CertifiedStreamStore + 'static>,
    advert_handler: Arc<dyn XNetAdvertHandler>,
    runtime_handle: runtime::Handle,
    tls: Arc<impl TlsConfig + 'static>,
    registry_client: Arc<impl RegistryClient + 'static>,
    shutdown_notify: Arc<Notify>,
    metrics: Arc<XNetEndpointMetrics>,
    log: ReplicaLogger,
) -> SocketAddr {
    let _guard = runtime_handle.enter();

    let listener = start_tcp_listener(address, &runtime_handle);
    let address = listener.local_addr().expect("Failed to get local addr.");

    let ctx = Arc::new(Context {
        semaphore: Arc::new(Semaphore::new(XNET_ENDPOINT_MAX_CONCURRENT_REQUESTS)),
        certified_stream_store,
        advert_handler,
        registry_client: registry_client.clone(),
        advert_rate_limiter: Default::default(),
        base_url: Url::parse(&format!("http://{address}/")).unwrap(),
        metrics: Arc::clone(&metrics),
        log: log.clone(),
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
        advert_handler: Arc<dyn XNetAdvertHandler>,
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
            certified_stream_store,
            advert_handler,
            runtime_handle.clone(),
            tls,
            registry_client,
            shutdown_notify.clone(),
            metrics,
            log.clone(),
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
    method: Method,
    body: Result<Bytes, axum::Error>,
    peer_node_id: Option<NodeId>,
    ctx: &Context<impl CertifiedStreamStore>,
) -> Response<Body> {
    let since = Instant::now();
    let (resource, response) = route_request_impl(url, method, body, peer_node_id, ctx);

    ctx.metrics
        .request_duration
        .with_label_values(&[resource, response.status().as_str()])
        .observe(since.elapsed().as_secs_f64());
    if response.status() == StatusCode::OK
        && let Some(size) = response.body().size_hint().exact()
    {
        ctx.metrics
            .response_size
            .with_label_values(&[resource])
            .observe(size as f64);
    }

    response
}

/// Implementation of `route_request()`, for easy instrumentation.
fn route_request_impl(
    url: Url,
    method: Method,
    body: Result<Bytes, axum::Error>,
    peer_node_id: Option<NodeId>,
    ctx: &Context<impl CertifiedStreamStore>,
) -> (&'static str, Response<Body>) {
    match url.path() {
        API_URL_STREAMS => (RESOURCE_STREAMS, handle_streams(ctx)),

        advert_url if advert_url.starts_with(API_URL_ADVERT_PREFIX) => {
            let subnet_id_str = &advert_url[API_URL_ADVERT_PREFIX.len()..];
            let Ok(subnet_id) = PrincipalId::from_str(subnet_id_str).map(SubnetId::from) else {
                return (
                    RESOURCE_ADVERT,
                    bad_request(format!(
                        "Invalid subnet ID: {subnet_id_str} in {advert_url}"
                    )),
                );
            };

            (
                RESOURCE_ADVERT,
                handle_advert(subnet_id, method, body, peer_node_id, ctx),
            )
        }

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
    json_response(&subnets)
}

/// Handles an advert from `source_subnet`: a certified stream header telling us
/// that it holds something we may not have seen.
///
/// Returns:
///  * HTTP 200 carrying our own certified header if the advert brought nothing
///    new, so the sender knows not to advertise it again;
///  * HTTP 204 if the advert contained something not yet covered by our latest
///    certified state, whether already known to the advert handler or not;
///  * HTTP 405 if the HTTP method was not `POST`;
///  * HTTP 429 if the caller is over its rate limit;
///  * HTTP 403 if the caller is not a node of `source_subnet`;
///  * HTTP 413 if the advert body was too large; or
///  * HTTP 400 if the advert could not be decoded or did not verify.
fn handle_advert(
    subnet_id: SubnetId,
    method: Method,
    body: Result<Bytes, axum::Error>,
    peer_node_id: Option<NodeId>,
    ctx: &Context<impl CertifiedStreamStore>,
) -> Response<Body> {
    let observe = |status: &str| ctx.metrics.adverts.with_label_values(&[status]).inc();

    // Helper closure, to allow for simpler, reliable instrumentation.
    #[allow(clippy::result_large_err)]
    let validate_advert = || {
        if method != Method::POST {
            return Err(method_not_allowed(
                format!("Adverts must be POSTed, got {method}"),
                "POST",
            ));
        }

        // `peer_node_id` is only `None` in tests. In production, the TLS handshake
        // always verifies that the caller is a registered node.
        let Some(node_id) = peer_node_id else {
            return Err(forbidden("Unreachable: no peer NodeId"));
        };

        if !ctx.advert_rate_limiter.try_acquire(node_id) {
            return Err(too_many_requests(format!(
                "Node {node_id} is over its advert rate limit"
            )));
        }

        // Only a node of `source_subnet` may advertise on its behalf. This also covers
        // `source_subnet` being unknown to the registry.
        if let Err(reason) =
            check_subnet_membership(node_id, subnet_id, ctx.registry_client.as_ref())
        {
            let msg = format!("Node {node_id} may not advertise for {subnet_id}: {reason}");
            warn!(ctx.log, "{}", msg);
            return Err(forbidden(msg));
        }

        // Anything beyond `ADVERT_MAX_BODY_BYTES`, or a body we failed to read. An
        // empty body (i.e. one we never read) fails to decode below.
        let body = match body {
            Ok(body) => body,

            Err(err) => {
                if let Some(source) = err.source()
                    && source.is::<LengthLimitError>()
                {
                    return Err(payload_too_large(format!("Advert too large: {err}")));
                }
                return Err(bad_request(format!("Could not read advert: {err}")));
            }
        };

        pb::CertifiedStreamSlice::proxy_decode(body.as_ref())
            .map_err(|err| bad_request(format!("Could not decode advert: {err}")))
    };

    let advert = match validate_advert() {
        Ok(advert) => advert,

        Err(response) => {
            observe(response.status().as_str());
            return response;
        }
    };

    match &ctx.advert_handler.handle_advert(subnet_id, advert) {
        Ok(outcome @ XNetAdvertOutcome::NothingNew) => {
            observe(outcome.as_str());
            // Prove to the sender that we have already consumed the advertised content by
            // replying with our own header.
            match ctx.advert_handler.certified_header(subnet_id) {
                Some(header) => proto_response::<_, pb::CertifiedStreamSlice>(header),

                // Unreachable, but no need to panic: the advert handler can only classify an
                // advert as `NothingNew` if it has a certified header to compare it with.
                None => no_content(),
            }
        }

        Ok(
            outcome @ (XNetAdvertOutcome::InPayload
            | XNetAdvertOutcome::Pooled
            | XNetAdvertOutcome::Duplicate
            | XNetAdvertOutcome::Actionable),
        ) => {
            observe(outcome.as_str());
            no_content()
        }

        Err(err @ XNetAdvertError::DecodeError(reason)) => {
            observe(err.as_str());
            let msg = format!("Could not decode advert for {subnet_id}: {reason}");
            warn!(ctx.log, "From node {peer_node_id:?}: {}", msg);
            bad_request(msg)
        }

        Err(err @ XNetAdvertError::InvalidSignature) => {
            observe(err.as_str());
            // A burst of adverts that decode but fail to verify likely indicates a subnet
            // whose public key has changed; a sustained rate of these is evidence of
            // malicious behavior.
            ctx.metrics
                .advert_verification_failures
                .with_label_values(&[&subnet_id.to_string()])
                .inc();
            let msg = format!("Advert for {subnet_id} failed to verify");
            warn!(ctx.log, "From node {peer_node_id:?}: {}", msg);
            bad_request(msg)
        }
    }
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
            proto_response::<_, pb::CertifiedStreamSlice>(stream)
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

/// Serializes the response as JSON.
pub(crate) fn json_response<R: Serialize>(r: &R) -> Response<Body> {
    let buf = serde_json::to_vec(r).expect("Could not serialize response");

    Response::builder()
        .header("Content-Type", "application/json")
        .body(buf.into())
        .unwrap()
}

/// Serializes the response as Protobuf.
pub(crate) fn proto_response<R, M>(r: R) -> Response<Body>
where
    M: ProtoProxy<R>,
{
    let buf = M::proxy_encode(r);

    // Headers borrowed from Spring Framework -- https://bit.ly/32EDqoo -- and Google's Protobuf
    // reference -- https://bit.ly/35Q4yml. Might come in handy for e.g. a browser extension.
    Response::builder()
        .header("Content-Type", "application/x-protobuf")
        .header("X-Protobuf-Schema", "certified_stream_slice.proto")
        .header("X-Protobuf-Message", "xnet.v1.CertifiedStreamSlice")
        .body(buf.into())
        .unwrap()
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

/// Produces a 413 Payload Too Large response with the given content.
fn payload_too_large<T: Into<Body>>(msg: T) -> Response<Body> {
    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .body(msg.into())
        .unwrap()
}

/// Produces a 405 Method Not Allowed response with the given content and set of
/// supported methods.
fn method_not_allowed<T: Into<Body>>(msg: T, allowed: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(hyper::header::ALLOW, allowed)
        .body(msg.into())
        .unwrap()
}

/// Produces a 429 Too Many Requests response with the given content.
fn too_many_requests<T: Into<Body>>(msg: T) -> Response<Body> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
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

/// Per-node token bucket rate limiter for adverts.
#[derive(Default)]
struct AdvertRateLimiter {
    buckets: Mutex<BTreeMap<NodeId, TokenBucket>>,
}

/// A token bucket for a node, consisting of the number of tokens at a given
/// instant. The number is recomputed on access, based on the elapsed time and
/// `ADVERT_RATE_LIMIT_PER_SECOND`, up to `ADVERT_RATE_LIMIT_BURST`.
struct TokenBucket {
    tokens: f64,
    updated: Instant,
}

impl AdvertRateLimiter {
    /// Takes a token on behalf of `node_id`; returns `false` if none is available.
    fn try_acquire(&self, node_id: NodeId) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();

        if buckets.len() > ADVERT_RATE_LIMIT_MAX_BUCKETS {
            // This runs on the critical path and is `O(n)`, but we expect to virtually
            // never have `ADVERT_RATE_LIMIT_MAX_BUCKETS` nodes advertising to us within
            // less than `ADVERT_RATE_LIMIT_BURST / ADVERT_RATE_LIMIT_PER_SECOND` seconds.
            buckets.retain(|_, bucket| {
                bucket.refill(now);
                bucket.tokens < ADVERT_RATE_LIMIT_BURST
            });
        }

        buckets
            .entry(node_id)
            .or_insert_with(|| TokenBucket {
                tokens: ADVERT_RATE_LIMIT_BURST,
                updated: now,
            })
            .try_take(now)
    }
}

impl TokenBucket {
    fn refill(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.updated).as_secs_f64();
        self.tokens =
            (self.tokens + elapsed * ADVERT_RATE_LIMIT_PER_SECOND).min(ADVERT_RATE_LIMIT_BURST);
        self.updated = now;
    }

    fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}
