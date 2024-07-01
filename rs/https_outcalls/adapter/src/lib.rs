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
use reqwest::{header::HeaderMap, redirect::Policy, Client, Proxy, Url};
pub use rpc_server::CanisterHttp;

use futures::{Future, Stream};
use ic_https_outcalls_service::canister_http_service_server::CanisterHttpServiceServer;
use ic_metrics::MetricsRegistry;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tonic::transport::{
    server::{Connected, Router},
    Server,
};
use tower::layer::util::Identity;
use tracing::info;

pub struct AdapterServer(Router<Identity>);

impl AdapterServer {
    pub fn new(config: Config, metrics: &MetricsRegistry) -> Self {
        let timeout = Duration::from_secs(config.http_connect_timeout_secs);

        // TODO: NET-1703
        let socks_client = match config.socks_proxy.parse::<Url>() {
            Ok(socks_url) => match Proxy::https(socks_url) {
                Ok(proxy) => {
                    let client = Client::builder()
                        .proxy(proxy)
                        .use_rustls_tls()
                        .https_only(true)
                        .http1_only()
                        .redirect(Policy::none())
                        .referer(false)
                        .default_headers(HeaderMap::new())
                        .connect_timeout(timeout)
                        .build();

                    if client.is_err() {
                        info!(
                            "Socks Client not created: Reqwest client builder failed: {:?}", client
                        );
                    }

                    client.ok()
                }
                Err(err) => {
                    info!(
                        "Socks Client not created: Failed to create https proxy: {:?}", err
                    );
                    None
                }
            },
            Err(err) => {
                info!(
                    "Socks Client not created: Failed to parse socks url: {:?}", err
                );
                None
            }
        };

        let https_client = Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .http1_only()
            .redirect(Policy::none())
            .referer(false)
            .default_headers(HeaderMap::new())
            .connect_timeout(timeout)
            .build()
            .expect("Failed to create HTTPS client");

        let canister_http = CanisterHttp::new(https_client, socks_client, metrics);

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
