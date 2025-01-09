//! The HTTP adapter makes http calls to the outside on behalf of the replica
//! This is part of the http calls from canister feature

/// Main module of HTTP adapter. Receives gRPC calls from replica and makes outgoing requests
mod rpc_server;

/// This module contains the basic configuration struct used to start up an adapter instance.
mod config;

/// Adapter metrics
mod metrics;

pub use config::{Config, IncomingSource};

use futures::StreamExt;
use ic_http_endpoints_async_utils::{incoming_from_nth_systemd_socket, incoming_from_path};
use ic_https_outcalls_service::https_outcalls_service_server::HttpsOutcallsServiceServer;
use ic_logger::ReplicaLogger;
use ic_metrics::MetricsRegistry;
use rpc_server::CanisterHttp;
use std::time::Duration;
use tonic::transport::Server;

pub fn start_server(
    log: &ReplicaLogger,
    metrics_registry: &MetricsRegistry,
    rt_handle: &tokio::runtime::Handle,
    config: config::Config,
) {
    let log = log.clone();
    let metrics_registry = metrics_registry.clone();
    let canister_http = CanisterHttp::new(config.clone(), log, &metrics_registry);

    let server = Server::builder()
        .timeout(Duration::from_secs(config.http_request_timeout_secs))
        .add_service(HttpsOutcallsServiceServer::new(canister_http));

    let incoming = match config.incoming_source {
        IncomingSource::Path(uds_path) => incoming_from_path(uds_path).boxed(),

        IncomingSource::Systemd =>
        // SAFETY: We are manged by systemd that is configured to pass socket as FD(3).
        // Additionally, this is the only call to connect with the systemd socket and
        // therefore we are sole owner.
        {
            unsafe { incoming_from_nth_systemd_socket(1) }.boxed()
        }
    };

    rt_handle.spawn(async move {
        server
            .serve_with_incoming(incoming)
            .await
            .expect("gRPC server crashed")
    });
}
