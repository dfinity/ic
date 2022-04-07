/// This binary is managed by systemd and added to the replica image.
/// The replica communicates with the HTTP adapter over unix domain sockets.
/// Relevant configuration files:
/// systemd service ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.service
/// systemd socket ic-os/guestos/rootfs/etc/systemd/system/ic-canister-http-adapter.socket
use clap::Parser;
use hyper::{client::connect::HttpConnector, Client};
use hyper_socks2::SocksConnector;
use hyper_tls::HttpsConnector;
use ic_async_utils::{
    ensure_single_systemd_socket, incoming_from_first_systemd_socket, incoming_from_path,
};
use ic_canister_http_adapter::{CanisterHttp, Cli, IncomingSource};
use ic_canister_http_adapter_service::http_adapter_server::HttpAdapterServer;
use ic_logger::{error, info, new_replica_logger_from_config};
use serde_json::to_string_pretty;
use tonic::transport::{Server, Uri};

#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();

    let config = match cli.get_config() {
        Ok(config) => config,
        Err(err) => {
            panic!("An error occurred while getting the config: {}", err);
        }
    };

    let (logger, _async_log_guard) = new_replica_logger_from_config(&config.logger);

    if config.incoming_source == IncomingSource::Systemd {
        // make sure we receive only one socket from systemd
        ensure_single_systemd_socket();
    }

    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);

    info!(
        logger,
        "Starting the adapter with config: {}",
        to_string_pretty(&config).unwrap()
    );

    match config.socks_proxy {
        Some(url) => {
            // socks URI should have protocol prepended. socks5://.....
            let proxy_connector = SocksConnector {
                proxy_addr: url
                    .to_string()
                    .parse::<Uri>()
                    .expect("Failed to parse socks url"),
                auth: None,
                connector: http_connector,
            };
            let mut https_connector = HttpsConnector::new_with_connector(proxy_connector);
            https_connector.https_only(true);
            let https_client = Client::builder().build::<_, hyper::Body>(https_connector);
            let canister_http = CanisterHttp::new(https_client, logger.clone());
            match config.incoming_source {
                IncomingSource::Path(uds_path) => Server::builder()
                    .add_service(HttpAdapterServer::new(canister_http))
                    .serve_with_incoming(incoming_from_path(uds_path))
                    .await
                    .map_err(|e| error!(logger, "Canister Http adapter crashed: {}", e))
                    .expect("gRPC server crashed"),
                IncomingSource::Systemd => Server::builder()
                    .add_service(HttpAdapterServer::new(canister_http))
                    .serve_with_incoming(incoming_from_first_systemd_socket())
                    .await
                    .map_err(|e| error!(logger, "Canister Http adapter crashed: {}", e))
                    .expect("gRPC server crashed"),
            };
        }
        None => {
            let mut https = HttpsConnector::new_with_connector(http_connector);
            https.https_only(true);
            let https_client = Client::builder().build::<_, hyper::Body>(https);
            let canister_http = CanisterHttp::new(https_client, logger.clone());
            match config.incoming_source {
                IncomingSource::Path(uds_path) => Server::builder()
                    .add_service(HttpAdapterServer::new(canister_http))
                    .serve_with_incoming(incoming_from_path(uds_path))
                    .await
                    .map_err(|e| error!(logger, "Canister Http adapter crashed: {}", e))
                    .expect("gRPC server crashed"),
                IncomingSource::Systemd => Server::builder()
                    .add_service(HttpAdapterServer::new(canister_http))
                    .serve_with_incoming(incoming_from_first_systemd_socket())
                    .await
                    .map_err(|e| error!(logger, "Canister Http adapter crashed: {}", e))
                    .expect("gRPC server crashed"),
            };
        }
    }
}
