//! The HTTP adapter makes http calls to the outside on behalf of the replica
//! This is part of the http calls from canister feature

mod cli;
/// Main module of HTTP adapter. Receives gRPC calls from replica and makes outgoing requests
mod rpc_server;

/// This module contains the basic configuration struct used to start up an adapter instance.
mod config;

/// Adapter metrics
mod metrics;

pub use cli::Cli;
pub use config::{Config, IncomingSource};
pub use rpc_server::{CanisterHttp, CanisterRequestBody};

use futures::{Future, Stream};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_socks2::SocksConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use ic_https_outcalls_service::canister_http_service_server::CanisterHttpServiceServer;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tonic::transport::{
    server::{Connected, Router},
    Server,
};
use tower::layer::util::Identity;

pub struct AdapterServer(Router<Identity>);

impl AdapterServer {
    pub fn new(config: Config, logger: ReplicaLogger, metrics: &MetricsRegistry) -> Self {
        // Socks client setup
        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);
        http_connector
            .set_connect_timeout(Some(Duration::from_secs(config.http_connect_timeout_secs)));
        // The proxy connnector requires a the URL scheme to be specified. I.e socks5://
        // Config validity check ensures that url includes scheme, host and port.
        // Therefore the parse 'Uri' will be in the correct format. I.e socks5://somehost.com:1080
        let proxy_connector = SocksConnector {
            proxy_addr: config
                .socks_proxy
                .parse()
                .expect("Failed to parse socks url."),
            auth: None,
            connector: http_connector.clone(),
        };
        let proxied_https_connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("Failed to set native roots")
            .https_only()
            .enable_http1()
            .wrap_connector(proxy_connector);

        // Https client setup.
        let builder = HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("Failed to set native roots");
        #[cfg(not(feature = "http"))]
        let builder = builder.https_only();
        #[cfg(feature = "http")]
        let builder = builder.https_or_http();

        let builder = builder.enable_http1();
        let canister_http = CanisterHttp::new(
            builder.wrap_connector(http_connector),
            proxied_https_connector,
            logger,
            metrics,
        );

        Self(
            Server::builder()
                .timeout(Duration::from_secs(config.http_request_timeout_secs))
                .add_service(CanisterHttpServiceServer::new(canister_http)),
        )
    }

    pub fn serve<S: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static>(
        self,
        stream: impl Stream<Item = Result<S, std::io::Error>>,
    ) -> impl Future<Output = Result<(), tonic::transport::Error>> {
        self.0.serve_with_incoming(stream)
    }
}
