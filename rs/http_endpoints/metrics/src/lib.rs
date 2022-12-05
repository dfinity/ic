use hyper::{server::conn::Http, Body, Request, Response, StatusCode};
use ic_async_utils::TcpAcceptor;
use ic_config::metrics::{Config, Exporter};
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces_registry::RegistryClient;
use ic_metrics::registry::MetricsRegistry;
use prometheus::{Encoder, IntCounterVec, TextEncoder};
use slog::{error, trace, warn};
use std::net::SocketAddr;
use std::string::String;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpSocket};
use tokio_io_timeout::TimeoutStream;
use tower::{
    limit::concurrency::GlobalConcurrencyLimitLayer, load_shed::error::Overloaded,
    timeout::error::Elapsed, util::BoxCloneService, BoxError, ServiceBuilder, ServiceExt,
};

const LOG_INTERVAL_SECS: u64 = 30;

const DEFAULT_ADAPTER_COLLECTION_TIMEOUT: Duration = Duration::from_secs(1);
/// Fraction of prometheus timeout that is applied to adapter collection.
/// Needed because we don't want adapter metrics scrape timeout to cause
/// a prometheus scrape timeout.
const PROMETHEUS_TIMEOUT_FRACTION: f64 = 0.5;
/// Header in prometheus scrape request that indicates the timeout used by scraping service.
const PROMETHEUS_TIMEOUT_HEADER: &str = "X-Prometheus-Scrape-Timeout-Seconds";

/// The type of a metrics runtime implementation.
pub struct MetricsHttpEndpoint {
    rt_handle: tokio::runtime::Handle,
    config: Config,
    metrics_registry: MetricsRegistry,
    crypto_tls: Option<(Arc<dyn RegistryClient>, Arc<dyn TlsHandshake + Send + Sync>)>,
    log: slog::Logger,
    metrics: MetricsEndpointMetrics,
}

#[derive(Error, Debug)]
struct HttpError {
    response: Response<Body>,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.response)
    }
}
impl From<BoxError> for HttpError {
    fn from(err: BoxError) -> Self {
        let builder = if err.is::<Overloaded>() {
            Response::builder().status(StatusCode::TOO_MANY_REQUESTS)
        } else if err.is::<Elapsed>() {
            Response::builder().status(StatusCode::GATEWAY_TIMEOUT)
        } else {
            Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR)
        };
        let response = builder
            .body(Body::from(""))
            .expect("Building response can't fail.");
        Self { response }
    }
}

#[derive(Clone)]
struct MetricsEndpointMetrics {
    connections_total: IntCounterVec,
}

impl MetricsEndpointMetrics {
    fn new(metrics_registry: MetricsRegistry) -> Self {
        Self {
            connections_total: metrics_registry.int_counter_vec(
                "metrics_endpoint_tcp_connections_total",
                "Total number of accepted TCP connections.",
                &["protocol"],
            ),
        }
    }
}

/// An implementation of the metrics runtime type.
impl MetricsHttpEndpoint {
    pub fn new(
        rt_handle: tokio::runtime::Handle,
        config: Config,
        metrics_registry: MetricsRegistry,
        registry_client: Arc<dyn RegistryClient>,
        crypto: Arc<dyn TlsHandshake + Send + Sync>,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(slog::o!("Application" => "MetricsRuntime"));

        let metrics = Self {
            rt_handle,
            config,
            metrics_registry: metrics_registry.clone(),
            crypto_tls: Some((registry_client, crypto)),
            log,
            metrics: MetricsEndpointMetrics::new(metrics_registry),
        };

        match metrics.config.exporter {
            Exporter::Http(socket_addr) => metrics.start_http(socket_addr),
            Exporter::Log => metrics.start_log(),
            Exporter::File(_) => {}
        };

        metrics
    }

    /// Create a MetricsHttpEndpoint supporting only HTTP for insecure use cases
    /// e.g. testing binaries where the node certificate may not be available.
    pub fn new_insecure(
        rt_handle: tokio::runtime::Handle,
        config: Config,
        metrics_registry: MetricsRegistry,
        log: &slog::Logger,
    ) -> Self {
        let log = log.new(slog::o!("Application" => "MetricsRuntime"));

        let metrics = Self {
            rt_handle,
            config,
            metrics_registry: metrics_registry.clone(),
            crypto_tls: None,
            log,
            metrics: MetricsEndpointMetrics::new(metrics_registry),
        };

        match metrics.config.exporter {
            Exporter::Http(socket_addr) => metrics.start_http(socket_addr),
            Exporter::Log => metrics.start_log(),
            Exporter::File(_) => {}
        };

        metrics
    }

    /// Spawn a background task which dump the metrics to the log.  This task
    /// does not terminate and if/when we support clean shutdown this task will
    /// need to be joined.
    fn start_log(&self) {
        let log = self.log.clone();
        let metrics_registry = self.metrics_registry.clone();
        self.rt_handle.spawn(async move {
            let encoder = TextEncoder::new();
            let mut interval = tokio::time::interval(Duration::from_secs(LOG_INTERVAL_SECS));
            loop {
                interval.tick().await;

                // Replica metrics need to be served even if some adapters are unresponsive.
                // To guarantee this, each adapter enforces either the default timeout (1s)
                let metrics_registry_replica = metrics_registry.clone();
                let metrics_registry_adapter = metrics_registry.clone();
                let (mf_replica, mut mf_adapters) = tokio::join!(
                    tokio::spawn(
                        async move { metrics_registry_replica.prometheus_registry().gather() }
                    ),
                    metrics_registry_adapter
                        .adapter_registry()
                        .gather(DEFAULT_ADAPTER_COLLECTION_TIMEOUT)
                );
                mf_adapters.append(&mut mf_replica.unwrap_or_default());

                let mut buffer = Vec::with_capacity(mf_adapters.len());
                encoder.encode(&mf_adapters, &mut buffer).unwrap();
                let metrics = String::from_utf8(buffer).unwrap();
                trace!(log, "{}", metrics);
            }
        });
    }

    /// Spawn a background task to accept and handle metrics connections.  This
    /// task does not terminate and if/when we support clean shutdown this
    /// task will need to be joined.
    fn start_http(&self, address: SocketAddr) {
        let metrics_registry = self.metrics_registry.clone();
        let log = self.log.clone();
        // we need to enter the tokio context in order to create the timeout layer and the tcp
        // socket
        let _enter = self.rt_handle.enter();
        let metrics_svc = ServiceBuilder::new()
            .load_shed()
            .timeout(Duration::from_secs(self.config.request_timeout_seconds))
            .layer(GlobalConcurrencyLimitLayer::new(
                self.config.max_concurrent_requests,
            ))
            .service_fn(move |req: Request<Body>| {
                // Clone again to ensure that `metrics_registry` outlives this closure.
                let metrics_registry = metrics_registry.clone();
                let encoder = TextEncoder::new();
                async move {
                    // Replica metrics need to be served even if some adapters are unresponsive.
                    // To guarantee this, each adapter enforces either the default timeout (1s) or
                    // a fraction of the timeout provided by Prometheus in the scrape request header.
                    let metrics_registry_replica = metrics_registry.clone();
                    let metrics_registry_adapter = metrics_registry.clone();
                    let (mf_replica, mut mf_adapters) = tokio::join!(
                        tokio::spawn(async move {
                            metrics_registry_replica.prometheus_registry().gather()
                        }),
                        metrics_registry_adapter.adapter_registry().gather(
                            req.headers()
                                .get(PROMETHEUS_TIMEOUT_HEADER)
                                .and_then(|h| h.to_str().ok())
                                .and_then(|h| Some(Duration::from_secs_f64(h.parse().ok()?)))
                                .map(|h| { h.mul_f64(PROMETHEUS_TIMEOUT_FRACTION) })
                                .unwrap_or(DEFAULT_ADAPTER_COLLECTION_TIMEOUT),
                        )
                    );
                    mf_adapters.append(&mut mf_replica.unwrap_or_default());

                    let mut buffer = Vec::with_capacity(mf_adapters.len());
                    encoder.encode(&mf_adapters, &mut buffer).unwrap();

                    Ok::<_, std::convert::Infallible>(Response::new(Body::from(buffer)))
                }
            })
            .map_result(move |result| -> Result<Response<Body>, HttpError> {
                match result {
                    Ok(response) => Ok(response),
                    Err(err) => Ok(HttpError::from(err).response),
                }
            });

        let metrics_svc = BoxCloneService::new(metrics_svc);
        let crypto_tls = self.crypto_tls.clone();
        // Temporarily listen on [::] so that we accept both IPv4 and IPv6 connections.
        // This requires net.ipv6.bindv6only = 0.  TODO: revert this once we have rolled
        // out IPv6 in prometheus and ic_p8s_service_discovery.
        let mut addr = "[::]:9090".parse::<SocketAddr>().unwrap();
        addr.set_port(address.port());
        let tcp_listener = start_listener(addr).unwrap_or_else(|err| {
            panic!("Could not start listener at addr = {}. err = {}", addr, err)
        });

        let metrics = self.metrics.clone();
        let connection_read_timeout_seconds = self.config.connection_read_timeout_seconds;
        let tcp_acceptor = TcpAcceptor::new(tcp_listener, self.config.max_outstanding_conections);
        self.rt_handle.spawn(async move {
            loop {
                let log = log.clone();
                let metrics_svc = metrics_svc.clone();
                let metrics = metrics.clone();
                let crypto_tls = crypto_tls.clone();
                if let Ok((tcp_stream, _)) = tcp_acceptor.accept().await {
                    tokio::spawn(async move {
                        let mut b = [0_u8; 1];
                        let (tcp_stream, _counter) = tcp_stream.take();
                        if tcp_stream.peek(&mut b).await.is_ok() && b[0] == 22 {
                            metrics
                                .connections_total
                                .with_label_values(&["https"])
                                .inc();

                            if let Some((registry_client, crypto)) = crypto_tls {
                                // Note: the unwrap() can't fail since we tested Some(crypto)
                                // above.
                                let registry_version = registry_client.get_latest_version();
                                match crypto
                                    .perform_tls_server_handshake_without_client_auth(
                                        tcp_stream,
                                        registry_version,
                                    )
                                    .await
                                {
                                    Err(e) => warn!(log, "TLS error: {}", e),
                                    Ok(stream) => {
                                        if let Err(e) = serve_connection_with_read_timeout(
                                            stream,
                                            metrics_svc,
                                            connection_read_timeout_seconds,
                                        )
                                        .await
                                        {
                                            trace!(log, "Connection error: {}", e);
                                        }
                                    }
                                };
                            }
                        } else {
                            metrics.connections_total.with_label_values(&["http"]).inc();
                            // Fallback to Http.
                            if let Err(e) = serve_connection_with_read_timeout(
                                tcp_stream,
                                metrics_svc,
                                connection_read_timeout_seconds,
                            )
                            .await
                            {
                                trace!(log, "Connection error: {}", e);
                            }
                        }
                    });
                }
            }
        });
    }
}

impl Drop for MetricsHttpEndpoint {
    fn drop(&mut self) {
        if let Exporter::File(ref path) = self.config.exporter {
            match std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(path)
            {
                Ok(mut file) => {
                    let encoder = TextEncoder::new();
                    let metric_families = self.metrics_registry.prometheus_registry().gather();
                    encoder
                        .encode(&metric_families, &mut file)
                        .unwrap_or_else(|err| {
                            error!(
                                self.log,
                                "Failed to encode metrics to file {}: {}",
                                path.display(),
                                err
                            );
                        });
                }
                Err(err) => {
                    error!(self.log, "Failed to open file {}: {}", path.display(), err);
                }
            }
        }
    }
}

async fn serve_connection_with_read_timeout<T: AsyncRead + AsyncWrite + 'static>(
    stream: T,
    metrics_svc: BoxCloneService<Request<Body>, Response<Body>, HttpError>,
    connection_read_timeout_seconds: u64,
) -> Result<(), hyper::Error> {
    let http = Http::new();
    let mut stream = TimeoutStream::new(stream);
    stream.set_read_timeout(Some(Duration::from_secs(connection_read_timeout_seconds)));
    let stream = Box::pin(stream);
    http.serve_connection(stream, metrics_svc).await
}

fn start_listener(local_addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = if local_addr.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    socket.bind(local_addr)?;
    socket.listen(128)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{
        client::{connect::HttpConnector, Client},
        Body, Error, Method, Request,
    };
    use ic_test_utilities_logger::with_test_replica_logger;
    use prometheus::{
        core::{Collector, Desc},
        proto::MetricFamily,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;
    use tokio::{
        net::{TcpSocket, TcpStream},
        sync::mpsc::{channel, Sender},
        time::sleep,
    };
    // Get a free port on this host to which we can connect transport to.
    fn get_free_localhost_port() -> std::io::Result<SocketAddr> {
        let socket = TcpSocket::new_v4()?;
        // This allows transport to bind to this address,
        //  even though the socket is already bound.
        socket.set_reuseport(true)?;
        socket.set_reuseaddr(true)?;
        socket.bind("127.0.0.1:0".parse().unwrap())?;
        socket.local_addr()
    }

    async fn send_request(
        client: &Client<HttpConnector, Body>,
        addr: SocketAddr,
    ) -> Result<Response<Body>, Error> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("http://{}", addr))
            .body(Body::from(""))
            .expect("Building the request failed.");

        client.request(req).await
    }

    async fn create_client_and_send_request(
        addr: SocketAddr,
    ) -> Result<Client<HttpConnector, Body>, Error> {
        let client: Client<HttpConnector, Body> = Client::builder().http2_only(true).build_http();

        send_request(&client, addr).await?;
        Ok(client)
    }

    /// Once we have reached the number of outstanding connection, new connections are refused.
    #[tokio::test]
    async fn test_max_outstanding_conections() {
        with_test_replica_logger(|log| async move {
            let rt_handle = tokio::runtime::Handle::current();
            let addr = get_free_localhost_port().unwrap();
            let config = Config {
                exporter: Exporter::Http(addr),
                ..Default::default()
            };
            let metrics_registry = MetricsRegistry::default();
            let _metrics_endpoint = MetricsHttpEndpoint::new_insecure(
                rt_handle,
                config.clone(),
                metrics_registry,
                &log.inner_logger.root,
            );

            // it is important to keep around the http clients so the connections don't get closed
            let mut clients = vec![];
            for _i in 0..config.max_outstanding_conections {
                let c = create_client_and_send_request(addr).await.expect(
                    "Creating a new http client/tcp connection and sending a message failed.",
                );
                clients.push(c);
            }
            // Check we hit the limit of live TCP connections by expecting a failure when yet
            // another request is send.
            assert!(create_client_and_send_request(addr).await.is_err());
        })
        .await
    }

    /// Once no bytes are read for the duration of 'connection_read_timeout_seconds', then
    /// the connection is dropped.
    #[tokio::test]
    async fn test_connection_read_timeout() {
        with_test_replica_logger(|log| async move {
            let rt_handle = tokio::runtime::Handle::current();
            let addr = get_free_localhost_port().unwrap();
            let config = Config {
                exporter: Exporter::Http(addr),
                connection_read_timeout_seconds: 2,
                ..Default::default()
            };
            let metrics_registry = MetricsRegistry::default();
            let _metrics_endpoint = MetricsHttpEndpoint::new_insecure(
                rt_handle,
                config.clone(),
                metrics_registry,
                &log.inner_logger.root,
            );

            let target_stream = TcpStream::connect(addr).await.unwrap();

            let (mut request_sender, connection) =
                hyper::client::conn::handshake(target_stream).await.unwrap();

            // spawn a task to poll the connection and drive the HTTP state
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    eprintln!("Error in connection: {}", e);
                }
            });

            let request = Request::builder()
                .method(Method::GET)
                .uri(format!("http://{}", addr))
                .header(hyper::header::HOST, "hyper.rs")
                .body(Body::from(""))
                .expect("Building the request failed.");
            let response = request_sender.send_request(request).await.unwrap();
            assert!(response.status() == StatusCode::OK);

            sleep(Duration::from_secs(
                config.connection_read_timeout_seconds + 1,
            ))
            .await;
            assert!(request_sender.ready().await.err().unwrap().is_closed());
        })
        .await
    }

    #[derive(Clone)]
    struct BlockingCollector {
        test_desc: Desc,
        sender: Sender<()>,
        collect_calls: Arc<AtomicUsize>,
    }

    impl BlockingCollector {
        fn new(sender: Sender<()>) -> Self {
            let mut hm = std::collections::HashMap::new();
            let _ = hm.insert("x".to_string(), "y".to_string());
            let test_desc =
                Desc::new("a".to_string(), "b".to_string(), vec!["c".to_string()], hm).unwrap();
            let collect_calls = Arc::new(AtomicUsize::new(0));

            Self {
                test_desc,
                sender,
                collect_calls,
            }
        }
    }

    impl Collector for BlockingCollector {
        fn desc(&self) -> Vec<&Desc> {
            vec![&self.test_desc]
        }

        fn collect(&self) -> Vec<MetricFamily> {
            self.collect_calls.fetch_add(1, Ordering::SeqCst);
            let tx = self.sender.clone();
            tokio::task::block_in_place(|| {
                tx.blocking_send(()).unwrap();
            });
            vec![]
        }
    }

    /// Test once the number of in-flight requests reaches 'max_concurrent_requests', a 429 should
    /// be returned for new requests.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_load_shedding() {
        with_test_replica_logger(|log| async move {
            let rt_handle = tokio::runtime::Handle::current();
            let addr = get_free_localhost_port().unwrap();
            let config = Config {
                exporter: Exporter::Http(addr),
                ..Default::default()
            };
            let metrics_registry = MetricsRegistry::default();
            let (tx, mut rx) = channel(1);
            let blocking_collector = metrics_registry.register(BlockingCollector::new(tx));
            let _metrics_endpoint = MetricsHttpEndpoint::new_insecure(
                rt_handle,
                config.clone(),
                metrics_registry,
                &log.inner_logger.root,
            );

            // Use a single client so we don't hit the max TCP connetions limit.
            let client = Client::builder()
                .http2_only(true)
                .retry_canceled_requests(false)
                .http2_max_concurrent_reset_streams(config.max_concurrent_requests * 2)
                .build_http();

            let mut set = tokio::task::JoinSet::new();

            assert_eq!(
                send_request(&client, addr).await.unwrap().status(),
                StatusCode::OK
            );
            // reset the counter to 0 after we confirmed there is a listening socket
            blocking_collector.collect_calls.store(0, Ordering::SeqCst);
            // Send 'max_concurrent_requests' and block their progress.
            for _i in 0..config.max_concurrent_requests {
                set.spawn({
                    let client = client.clone();
                    async move {
                        assert_eq!(
                            send_request(&client, addr).await.unwrap().status(),
                            StatusCode::OK
                        );
                    }
                });
            }

            // What until all requests reached the blocking/sync point.
            while blocking_collector.collect_calls.load(Ordering::SeqCst)
                != config.max_concurrent_requests
            {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                send_request(&client, addr).await.unwrap().status(),
                StatusCode::TOO_MANY_REQUESTS
            );

            // unblock and join the tasks that have sent the initial requets
            for _i in 0..config.max_concurrent_requests + 1 {
                rx.recv().await.unwrap();
            }
            for _i in 0..config.max_concurrent_requests {
                set.join_next().await.unwrap().unwrap();
            }
        })
        .await
    }

    /// If the downstream service is stuck return 504.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_request_timeout() {
        with_test_replica_logger(|log| async move {
            let rt_handle = tokio::runtime::Handle::current();
            let addr = get_free_localhost_port().unwrap();
            let config = Config {
                exporter: Exporter::Http(addr),
                request_timeout_seconds: 2,
                ..Default::default()
            };
            let metrics_registry = MetricsRegistry::default();
            let (tx, mut rx) = channel(1);
            let _blocking_collector = metrics_registry.register(BlockingCollector::new(tx));
            let _metrics_endpoint = MetricsHttpEndpoint::new_insecure(
                rt_handle,
                config.clone(),
                metrics_registry,
                &log.inner_logger.root,
            );

            // Use a single client so we don't hit the max TCP connetions limit.
            let client = Client::builder()
                .http2_only(true)
                .retry_canceled_requests(false)
                .http2_max_concurrent_reset_streams(config.max_concurrent_requests * 2)
                .build_http();

            assert_eq!(
                send_request(&client, addr).await.unwrap().status(),
                StatusCode::OK
            );

            assert_eq!(
                send_request(&client, addr).await.unwrap().status(),
                StatusCode::GATEWAY_TIMEOUT
            );
            rx.recv().await.unwrap();
            rx.recv().await.unwrap();
        })
        .await
    }

    // Test if slow downstream services don't cause connection drop.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_connection_is_alive_with_slow_downstream() {
        with_test_replica_logger(|log| async move {
            let rt_handle = tokio::runtime::Handle::current();
            let addr = get_free_localhost_port().unwrap();
            let config = Config {
                exporter: Exporter::Http(addr),
                request_timeout_seconds: 2,
                connection_read_timeout_seconds: 3,
                ..Default::default()
            };
            let metrics_registry = MetricsRegistry::default();
            let (tx, mut rx) = channel(1);
            let _blocking_collector = metrics_registry.register(BlockingCollector::new(tx));
            let _metrics_endpoint = MetricsHttpEndpoint::new_insecure(
                rt_handle,
                config.clone(),
                metrics_registry,
                &log.inner_logger.root,
            );

            // Use a single client so we don't hit the max TCP connetions limit.
            let client = Client::builder()
                .http2_only(true)
                .retry_canceled_requests(false)
                .http2_max_concurrent_reset_streams(config.max_concurrent_requests * 2)
                .build_http();

            assert_eq!(
                send_request(&client, addr).await.unwrap().status(),
                StatusCode::OK
            );
            let n = config.connection_read_timeout_seconds / config.request_timeout_seconds + 2;
            for _i in 0..n {
                assert_eq!(
                    send_request(&client, addr).await.unwrap().status(),
                    StatusCode::GATEWAY_TIMEOUT
                );
            }
            for _i in 0..n + 1 {
                rx.recv().await.unwrap();
            }
        })
        .await
    }
}
