use crate::api::disk_encryption_key_exchange_service_server::{
    DiskEncryptionKeyExchangeService, DiskEncryptionKeyExchangeServiceServer,
};
use crate::api::{
    GetDiskEncryptionKeyRequest, GetDiskEncryptionKeyResponse, GetNodeSigningKeyRequest,
    GetNodeSigningKeyResponse, SignalStatusRequest, SignalStatusResponse,
};
use crate::custom_data::GetDiskEncryptionKeyTokenCustomData;
use crate::registry::get_blessed_guest_launch_measurements_from_registry;
use crate::{api, DiskEncryptionKeyProvider, Partition};
use anyhow::Context as _;
use anyhow::Result as AnyhowResult;
use attestation::attestation_report::SevAttestationPackageGenerator;
use attestation::certificates::CertificateProvider;
use attestation::types::SevAttestationPackage;
use attestation::verify::verify_attestation_report;
use der::asn1::OctetStringRef;
use futures_util::TryStreamExt;
use ic_crypto_internal_csp::Csp;
use ic_interfaces::crypto::BasicSigner;
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::types::v1::NodeId as NodeIdProto;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::hostos_version::NodeId;
use ic_registry_local_store::LocalStoreImpl;
use ic_types::crypto::NodeIdProof;
use ic_types::node_id_into_protobuf;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use sev::certs::snp::builtin::milan;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tls::{TlsConnectionInfoForUpgrade, TlsStreamWrapper};
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::sync::watch::Sender;
use tokio::sync::Notify;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tonic::{async_trait, Request, Response, Status};

mod tls;

#[derive(Error, Debug)]
pub enum DiskEncryptionKeyExchangeServerError {
    #[error("Failed to bind: {0}")]
    CouldNotBind(std::io::Error),
}

pub struct DiskEncryptionKeyExchangeServer {
    /// Used to signal that the server should be terminated.
    shutdown_token: CancellationToken,
}

impl DiskEncryptionKeyExchangeServer {
    /// Create a new `DiskEncryptionKeyExchangeServer` and start it immediately. The server runs as
    /// long as the returned instance is alive.
    ///
    /// Returns an error if the server fails to start.
    pub async fn start_new(
        runtime_handle: Handle,
        key_exchange_service: Arc<impl DiskEncryptionKeyExchangeService>,
    ) -> Result<Self, DiskEncryptionKeyExchangeServerError> {
        let tls_acceptor = TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![
                        CertificateDer::from_pem_slice(include_bytes!("../../server_cert.pem"))
                            .expect("Hardcoded certificate is invalid"),
                    ],
                    PrivateKeyDer::from_pem_slice(include_bytes!("../../server_key.pem"))
                        .expect("Hardcoded key is invalid"),
                )
                .expect("Hardcoded configuration is invalid"),
        ));

        let tcp_listener =
            TcpListener::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), api::PORT))
                .await
                .map_err(DiskEncryptionKeyExchangeServerError::CouldNotBind)?;
        let stream = TcpListenerStream::new(tcp_listener)
            .and_then(move |tcp_stream| tls_acceptor.accept(tcp_stream))
            .map_ok(TlsStreamWrapper);

        println!(
            "Disk encryption key exchange server listening on port {}",
            api::PORT
        );

        // Cancellation token for shutdown
        let shutdown_token = CancellationToken::new();
        let shutdown_token_clone = shutdown_token.clone();

        runtime_handle.spawn(async move {
            Server::builder()
                .add_service(DiskEncryptionKeyExchangeServiceServer::from_arc(
                    key_exchange_service,
                ))
                .serve_with_incoming_shutdown(stream, async move {
                    shutdown_token_clone.cancelled().await
                })
                .await
        });

        Ok(Self { shutdown_token })
    }
}

impl Drop for DiskEncryptionKeyExchangeServer {
    fn drop(&mut self) {
        self.shutdown_token.cancel();
    }
}

pub struct DiskEncryptionKeyExchangeServiceImpl {
    disk_encryption_key_provider: Arc<DiskEncryptionKeyProvider>,
    attestation_package_generator: Arc<SevAttestationPackageGenerator>,
    success: Sender<bool>,
    node_id: NodeId,
    signer: Arc<dyn BasicSigner<NodeIdProof> + Send + Sync>,
    registry_client: Arc<dyn RegistryClient + Send + Sync>,
}

impl DiskEncryptionKeyExchangeServiceImpl {
    pub fn new(
        attestation_package_generator: Arc<SevAttestationPackageGenerator>,
        disk_encryption_key_provider: Arc<DiskEncryptionKeyProvider>,
        success: Sender<bool>,
        node_id: NodeId,
        signer: Arc<dyn BasicSigner<NodeIdProof> + Send + Sync>,
        registry_client: Arc<dyn RegistryClient + Send + Sync>,
    ) -> Self {
        Self {
            attestation_package_generator,
            disk_encryption_key_provider,
            success,
            node_id,
            signer,
            registry_client,
        }
    }

    fn get_blessed_measurements(&self) -> Result<Vec<Vec<u8>>, Status> {
        let nns_registry_client = RegistryClientImpl::new(
            // TODO: use the correct NNS registry path
            Arc::new(LocalStoreImpl::new(
                "/var/lib/ic/data/ic_registry_local_store",
            )),
            /*metrics_registry=*/ None,
        );
        nns_registry_client
            .try_polling_latest_version(usize::MAX)
            .map_err(|e| {
                Status::internal(format!("Failed to poll latest version from registry: {e}"))
            })?;

        let blessed_measurements = get_blessed_guest_launch_measurements_from_registry(
            &nns_registry_client,
        )
        .map_err(|e| {
            Status::internal(format!(
                "Failed to get blessed measurements from registry: {e}"
            ))
        })?;
        Ok(blessed_measurements)
    }

    fn generate_sev_attestation_package(
        &self,
        attestation_report_custom_data: &GetDiskEncryptionKeyTokenCustomData,
    ) -> AnyhowResult<SevAttestationPackage> {
        self.attestation_package_generator
            .generate_attestation_package(attestation_report_custom_data)
            .context("Failed to generate attestation report")
    }
}

#[async_trait]
impl DiskEncryptionKeyExchangeService for DiskEncryptionKeyExchangeServiceImpl {
    async fn get_disk_encryption_key(
        &self,
        request: Request<GetDiskEncryptionKeyRequest>,
    ) -> Result<Response<GetDiskEncryptionKeyResponse>, Status> {
        let tls_shared_key_for_attestation = request
            .extensions()
            .get::<TlsConnectionInfoForUpgrade>()
            .ok_or_else(|| Status::internal("CustomConnectionInfo is missing"))?
            .tls_shared_key_for_attestation;
        let request = request.into_inner();

        let Some(attestation_report) = request.sev_attestation_package else {
            return Err(Status::invalid_argument(
                "sev_attestation_package must not be empty",
            ));
        };

        let attestation_report_custom_data = GetDiskEncryptionKeyTokenCustomData {
            tls_shared_key_for_attestation: OctetStringRef::new(&tls_shared_key_for_attestation)
                .expect("Could not encode TLS shared key"),
        };

        verify_attestation_report(
            &attestation_report,
            milan::ARK,
            &self.get_blessed_measurements()?,
            &attestation_report_custom_data,
        )
        .map_err(|e| {
            Status::invalid_argument(format!("Attestation report verification failed: {}", e))
        })?;

        let my_attestation_package = self
            .generate_sev_attestation_package(&attestation_report_custom_data)
            .inspect_err(|err| {
                // TODO: log the error
                eprintln!("Failed to generate attestation package: {}", err);
                // log::warn!("Failed to generate attestation report: {}", err);
            })
            .ok();

        Ok(Response::new(GetDiskEncryptionKeyResponse {
            key: Some(
                self.disk_encryption_key_provider
                    .get_disk_encryption_key(Partition::Store)
                    .map_err(|e| {
                        Status::internal(format!("Failed to get disk encryption key: {}", e))
                    })?
                    .into_bytes(),
            ),
            sev_attestation_package: my_attestation_package,
        }))
    }

    async fn get_node_signing_key(
        &self,
        request: Request<GetNodeSigningKeyRequest>,
    ) -> Result<Response<GetNodeSigningKeyResponse>, Status> {
        let request = request.into_inner();
        // Sign the challenge if provided.
        let proof = request.challenge.and_then(|challenge| {
            self.signer
                .sign_basic(
                    &NodeIdProof(challenge.clone()),
                    self.node_id,
                    self.registry_client.get_latest_version(),
                )
                .ok() // TODO: log error
                .map(|result| result.get().0)
        });

        Ok(Response::new(GetNodeSigningKeyResponse {
            node_id: Some(node_id_into_protobuf(self.node_id)),
            proof,
        }))
    }

    async fn signal_status(
        &self,
        request: Request<SignalStatusRequest>,
    ) -> Result<Response<SignalStatusResponse>, Status> {
        let _ignored = self.success.send(request.get_ref().success == Some(true));
        Ok(Response::new(SignalStatusResponse {}))
    }
}
