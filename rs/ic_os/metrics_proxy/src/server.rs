use crate::config::{HttpProxy, ListenerSpec, Protocol};
use crate::proxy;
use crate::tokiotimer::TokioTimer;
use axum::debug_handler;
use axum::extract::Request;
use axum::extract::State;
use axum::http;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::middleware::map_response;
use axum::{Router, routing::get};
use axum_prometheus::metrics_exporter_prometheus::PrometheusHandle;
use axum_prometheus::{GenericMetricLayer, Handle};
use hyper;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto;
use log::{debug, error};
use rustls;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};
use tower::Service;
use tower_http;

#[derive(Debug)]
pub enum ServeErrorKind {
    ListenError(std::io::Error),
    RustlsError(rustls::Error),
}

impl fmt::Display for ServeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ServeErrorKind::ListenError(e) => format!("{e}"),
                ServeErrorKind::RustlsError(ef) => format!("{ef}"),
            }
        )
    }
}

#[derive(Debug)]
pub struct StartError {
    addr: SocketAddr,
    error: ServeErrorKind,
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cannot listen on {}: {}", self.addr, self.error)
    }
}

enum ServerKind {
    PrometheusMetricsProxy(HttpProxy),
    PrometheusMetricsServer(ListenerSpec),
}

pub struct Server {
    config: ServerKind,
    metrics_collector: Option<GenericMetricLayer<'static, PrometheusHandle, Handle>>,
    metrics_handle: Option<PrometheusHandle>,
}

impl From<HttpProxy> for Server {
    fn from(config: HttpProxy) -> Self {
        Self::for_metrics_proxy(config)
    }
}

impl Server {
    #[must_use]
    /// Configures this `Server` to proxy one or more handlers
    /// to a backend endpoint each.
    pub fn for_metrics_proxy(config: HttpProxy) -> Self {
        Server {
            config: ServerKind::PrometheusMetricsProxy(config),
            metrics_collector: None,
            metrics_handle: None,
        }
    }

    #[must_use]
    /// Configures this `Server` to serve Prometheus metrics
    /// collected during proxying.
    pub fn for_service_metrics(listen_on: ListenerSpec) -> Self {
        Server {
            config: ServerKind::PrometheusMetricsServer(listen_on),
            metrics_collector: None,
            metrics_handle: None,
        }
    }

    #[must_use]
    /// Enables telemetry collection.
    pub fn with_telemetry(self, ml: GenericMetricLayer<'static, PrometheusHandle, Handle>) -> Self {
        Server {
            metrics_collector: Some(ml),
            ..self
        }
    }

    #[must_use]
    /// Enables telemetry collection.
    pub fn with_metrics_handle(self, mh: PrometheusHandle) -> Self {
        Server {
            metrics_handle: Some(mh),
            ..self
        }
    }

    /// Starts an HTTP or HTTPS server on the configured host and port,
    /// proxying requests to each one of the targets defined in the
    /// `handlers` of the `HttpProxy` config.
    ///
    /// # Errors
    /// * `StartError` is returned if the server fails to start.
    pub async fn serve(self) -> Result<(), StartError> {
        // Short helper to issue backend request.
        #[debug_handler]
        async fn handle_with_proxy(
            headers: HeaderMap,
            State(proxy): State<proxy::MetricsProxier>,
        ) -> (StatusCode, HeaderMap, Bytes) {
            proxy.handle(headers).await
        }

        // Short helper to map 408 from request response timeout layer to 504.
        async fn gateway_timeout<B>(
            mut response: axum::response::Response<B>,
        ) -> axum::response::Response<B> {
            if response.status() == http::StatusCode::REQUEST_TIMEOUT {
                *response.status_mut() = http::StatusCode::GATEWAY_TIMEOUT;
            }
            response
        }

        let listener = match &self.config {
            ServerKind::PrometheusMetricsProxy(config) => config.listen_on.clone(),
            ServerKind::PrometheusMetricsServer(listen_on) => listen_on.clone(),
        };

        let mut router: Router<_> = Router::new();
        let bodytimeout =
            tower_http::timeout::RequestBodyTimeoutLayer::new(listener.header_read_timeout);

        router = match self.config {
            ServerKind::PrometheusMetricsProxy(config) => {
                for (path, target) in config.handlers.clone() {
                    let cache_duration = target.clone().cache_duration;
                    let state = proxy::MetricsProxier::from(target);
                    let mut method_router = get(handle_with_proxy)
                        .with_state(state)
                        .layer(tower::ServiceBuilder::new().layer(bodytimeout.clone()));
                    if Duration::from(cache_duration) > Duration::new(0, 0) {
                        method_router = method_router
                            .layer(crate::cache::CacheLayer::new(cache_duration.into()));
                    }
                    router = router.route(path.as_str(), method_router);
                }
                router
            }
            ServerKind::PrometheusMetricsServer(_) => match self.metrics_handle {
                Some(handle) => router.route("/metrics", get(|| async move { handle.render() })),
                None => router,
            },
        };

        // Second-to-last the timeout layer.
        // The timeout layer returns HTTP status code 408 if the backend
        // fails to respond on time.  When this happens, we map that code
        // to 503 Gateway Timeout.
        // (Contrast with backend down -- this usually requires a response
        // of 502 Bad Gateway, which is already issued by the client handler.)
        router = router
            .layer(tower_http::timeout::TimeoutLayer::new(
                listener.request_response_timeout,
            ))
            .layer(map_response(gateway_timeout));

        // Then, finally, the telemetry layer.
        // Experimentally, if the telemetry layer does not go last, then
        // whatever errors the timeout layers bubble up, the telemetry
        // layer cannot register as an HTTP error.
        if let Some(collector_layer) = self.metrics_collector.clone() {
            router = router.layer(collector_layer);
        }

        let incoming = TcpListener::bind(&listener.sockaddr)
            .await
            .map_err(|error| StartError {
                addr: listener.sockaddr,
                error: ServeErrorKind::ListenError(error),
            })?;

        let acceptor = match &listener.protocol {
            Protocol::Http => None,
            Protocol::Https { certificate, key } => {
                let mut server_config = ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certificate.clone(), key.clone_key())
                    .map_err(|error| StartError {
                        addr: listener.sockaddr,
                        error: ServeErrorKind::RustlsError(error),
                    })?;
                server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                Some(TlsAcceptor::from(Arc::new(server_config)))
            }
        };

        loop {
            match incoming.accept().await {
                Err(err) => {
                    error!("Error accepting new connection: {:?}", err);
                }
                Ok((socket, addr)) => {
                    debug!("Accepted connection from {}", addr);
                    let tower_service = router.clone();
                    let hyper_service =
                        hyper::service::service_fn(move |request: Request<Incoming>| {
                            tower_service.clone().clone().call(request)
                        });
                    let mut builder = auto::Builder::new(TokioExecutor::new());
                    builder
                        .http1()
                        .timer(TokioTimer)
                        .header_read_timeout(listener.header_read_timeout);
                    let tls = acceptor.clone();
                    tokio::task::spawn(async move {
                        match tls {
                            None => {
                                let io = hyper_util::rt::tokio::TokioIo::new(socket);
                                debug!("About to call server to serve {}", addr);
                                let ret = builder
                                    .serve_connection_with_upgrades(io, hyper_service)
                                    .await;
                                if let Err(err) = ret {
                                    error!("Error serving plain request from {}: {:?}", addr, err);
                                }
                            }
                            Some(tls) => {
                                debug!("About to handshake TLS with {}", addr);
                                let ret = tls.accept(socket).await;
                                if let Err(err) = ret {
                                    error!("Error during TLS handshake from {}: {:?}", addr, err);
                                    return;
                                }
                                let io = hyper_util::rt::tokio::TokioIo::new(ret.unwrap());
                                debug!("About to call TLS-enabled server to serve {}", addr);
                                let ret2 = builder
                                    .serve_connection_with_upgrades(io, hyper_service)
                                    .await;
                                if let Err(err) = ret2 {
                                    error!("Error serving TLS request from {}: {:?}", addr, err);
                                }
                            }
                        }
                    });
                }
            };
        }
    }
}
