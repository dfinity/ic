//! The HTTP adapter makes http calls to the outside on behalf of the replica
//! This is part of the http calls from canister feature

mod cli;
/// Main module of HTTP adapter. Receives gRPC calls from replica and makes outgoing requests
mod rpc_server;

/// This module contains the basic configuration struct used to start up an adapter instance.
mod config;

pub use cli::Cli;
pub use config::{Config, IncomingSource};
pub use rpc_server::CanisterHttp;

use byte_unit::Byte;
use futures::Future;
use futures_core::stream::Stream;
use hyper::{
    client::connect::{Connect, HttpConnector},
    Client,
};
use hyper_socks2::SocksConnector;
use hyper_tls::HttpsConnector;
use ic_canister_http_service::canister_http_service_server::CanisterHttpServiceServer;
use ic_logger::ReplicaLogger;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tonic::transport::{
    server::{Connected, Router},
    Server, Uri,
};
use tower::layer::util::Identity;

pub struct AdapterServer(Router<Identity>);

impl AdapterServer {
    // The 'enforce_http' flat is used to execute unit tests with http.
    // It should be removed in the future. NET-1074
    pub fn new(config: Config, logger: ReplicaLogger, enforce_https: bool) -> Self {
        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);
        http_connector
            .set_connect_timeout(Some(Duration::from_secs(config.http_connect_timeout_secs)));
        match &config.socks_proxy {
            Some(url) => {
                // The proxy connnector requires a the URL scheme to be specified. I.e socks5://
                // Config validity check ensures that url includes scheme, host and port.
                // Therefore the parse 'Uri' will be in the correct format. I.e socks5://somehost.com:1080
                let proxy_connector = SocksConnector {
                    proxy_addr: url.parse::<Uri>().expect("Failed to parse socks url."),
                    auth: None,
                    connector: http_connector,
                };
                let mut https_connector = HttpsConnector::new_with_connector(proxy_connector);
                https_connector.https_only(enforce_https);
                let https_client = Client::builder().build::<_, hyper::Body>(https_connector);
                Self::new_with_client(https_client, config, logger)
            }
            None => {
                let mut https_connector = HttpsConnector::new_with_connector(http_connector);
                https_connector.https_only(enforce_https);
                let https_client = Client::builder().build::<_, hyper::Body>(https_connector);
                Self::new_with_client(https_client, config, logger)
            }
        }
    }

    fn new_with_client<C: Clone + Connect + Send + Sync + 'static>(
        client: Client<C>,
        config: Config,
        logger: ReplicaLogger,
    ) -> Self {
        let canister_http = CanisterHttp::new(
            client,
            Byte::from(config.http_request_size_limit_bytes),
            logger,
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
