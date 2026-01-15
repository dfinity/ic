use crate::DiskEncryptionKeyExchangeError;
use crate::tls::SkipClientCertificateCheck;
use guest_upgrade_shared::api::disk_encryption_key_exchange_service_server::DiskEncryptionKeyExchangeService;
use guest_upgrade_shared::api::disk_encryption_key_exchange_service_server::DiskEncryptionKeyExchangeServiceServer;
use http_body_util::BodyExt;
use hyper::server::conn::http2::Builder;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use rcgen::CertifiedKey;
use rustls::version::TLS13;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer},
    },
};
use tokio_util::sync::CancellationToken;
use tonic::Status;
use tonic::body::BoxBody;
use tower::ServiceExt;
use tower_http::ServiceBuilderExt;

#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub certificates: Vec<CertificateDer<'static>>,
}

pub struct DiskEncryptionKeyExchangeServer {
    /// Used to signal that the server should be terminated.
    shutdown_token: CancellationToken,
}

impl DiskEncryptionKeyExchangeServer {
    /// Create a new `DiskEncryptionKeyExchangeServer` and start it immediately. The server runs as
    /// long as the returned instance is alive. The server is shut down asynchronously when the
    /// instance is dropped.
    ///
    /// Returns an error if the server fails to start.
    pub async fn start_new(
        runtime: Handle,
        port: u16,
        certified_key: CertifiedKey,
        service_impl: Arc<impl DiskEncryptionKeyExchangeService>,
    ) -> Result<Self, DiskEncryptionKeyExchangeError> {
        println!("Starting Disk encryption key exchange server on port {port}");

        // Cancellation token for shutdown
        let shutdown_token = CancellationToken::new();

        // Convert rcgen certificate to rustls format
        let cert_der = CertificateDer::from(certified_key.cert.der().to_vec());
        let key_der =
            PrivateKeyDer::try_from(certified_key.key_pair.serialize_der()).map_err(|e| {
                DiskEncryptionKeyExchangeError::ServerStartError(format!(
                    "Failed to parse private key: {e}"
                ))
            })?;

        let tls_config = ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_client_cert_verifier(Arc::new(SkipClientCertificateCheck))
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| {
                DiskEncryptionKeyExchangeError::ServerStartError(format!(
                    "Failed to create TLS config: {e}"
                ))
            })?;
        let tls_config = Arc::new(tls_config);

        let tcp_listener = TcpListener::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port))
            .await
            .map_err(|e| {
                DiskEncryptionKeyExchangeError::ServerStartError(format!(
                    "Failed to bind to port {port}: {e}"
                ))
            })?;

        println!("Disk encryption key exchange server bound to port {port} and ready");

        let shutdown_token_c = shutdown_token.clone();
        let runtime_c = runtime.clone();
        runtime.spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown_token_c.cancelled() => {
                        println!("Server shutting down");
                        break;
                    }
                    accept = tcp_listener.accept() => {
                        match accept {
                            Ok((conn, _addr)) =>
                                Self::serve_connection(
                                    &runtime_c,
                                    conn,
                                    tls_config.clone(),
                                    service_impl.clone()),
                            Err(e) => {
                                eprintln!("Error accepting connection: {e}");
                                continue;
                            }
                        };
                    }
                }
            }
        });

        Ok(Self { shutdown_token })
    }

    fn serve_connection(
        runtime_handle: &Handle,
        tcp_stream: TcpStream,
        tls_config: Arc<ServerConfig>,
        service: Arc<impl DiskEncryptionKeyExchangeService>,
    ) {
        let http = Builder::new(TokioExecutor::new());
        let tls_acceptor = TlsAcceptor::from(tls_config);

        runtime_handle.spawn(async move {
            let mut certificates = Vec::new();

            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    eprintln!("TLS handshake failed: {e}");
                    return;
                }
            };

            if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
                for cert in certs {
                    certificates.push(cert.clone());
                }
            }

            let service = tower::ServiceBuilder::new()
                .add_extension(ConnInfo { certificates })
                .service(DiskEncryptionKeyExchangeServiceServer::from_arc(service))
                .map_request(|req: hyper::Request<hyper::body::Incoming>| {
                    req.map(|body| BoxBody::new(body.map_err(|e| Status::from_error(Box::new(e)))))
                });

            if let Err(e) = http
                .serve_connection(TokioIo::new(tls_stream), TowerToHyperService::new(service))
                .await
            {
                eprintln!("Error serving connection: {e:?}");
            }
        });
    }
}

impl Drop for DiskEncryptionKeyExchangeServer {
    fn drop(&mut self) {
        self.shutdown_token.cancel();
    }
}
