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
pub use rpc_server::CanisterHttp;

use futures::{Future, Stream};
use ic_async_utils::{incoming_from_first_systemd_socket, incoming_from_path};
use ic_https_outcalls_service::https_outcalls_service_server::HttpsOutcallsServiceServer;
use ic_logger::{error, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tonic::transport::{
    server::{Connected, Router},
    Server,
};
use tower::layer::util::Identity;

pub fn start_server(
    log: &ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt_handle: &tokio::runtime::Handle,
    config: config::Config,
) {
    let log = log.clone();
    let metrics_registry = metrics_registry.clone();
    rt_handle.spawn(async move {
        // Create server with https enforcement.
        let server = AdapterServer::new(config.clone(), log.clone(), &metrics_registry);
        match config.incoming_source {
            IncomingSource::Path(uds_path) => server
                .serve(incoming_from_path(uds_path))
                .await
                .map_err(|e| error!(log, "Canister Http adapter crashed: {}", e))
                .expect("gRPC server crashed"),
            IncomingSource::Systemd => server
                // SAFETY: We are manged by systemd that is configured to pass socket as FD(3).
                // Additionally, this is the only call to connect with the systemd socket and
                // therefore we are sole owner.
                .serve(unsafe { incoming_from_first_systemd_socket() })
                .await
                .map_err(|e| error!(log, "Canister Http adapter crashed: {}", e))
                .expect("gRPC server crashed"),
        };
    });
}

/// Start the HttpsOutcallsService server.
pub struct AdapterServer(Router<Identity>);

impl AdapterServer {
    pub fn new(config: Config, logger: ReplicaLogger, metrics: &MetricsRegistry) -> Self {
        let canister_http = CanisterHttp::new(config.clone(), logger, metrics);

        Self(
            Server::builder()
                .timeout(Duration::from_secs(config.http_request_timeout_secs))
                .add_service(HttpsOutcallsServiceServer::new(canister_http)),
        )
    }

    pub fn serve<S: AsyncRead + AsyncWrite + Connected + Unpin + Send + 'static>(
        self,
        stream: impl Stream<Item = Result<S, std::io::Error>>,
    ) -> impl Future<Output = Result<(), tonic::transport::Error>> {
        self.0.serve_with_incoming(stream)
    }
}
