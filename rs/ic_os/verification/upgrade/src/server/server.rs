use crate::tls::{TlsConnectionInfoForUpgrade, TlsStreamWrapper};
use anyhow::Context as _;
use anyhow::Result as AnyhowResult;
use attestation::attestation_report::SevAttestationPackageGenerator;
use attestation::certificates::CertificateProvider;
use attestation::types::SevAttestationPackage;
use attestation::verify::verify_attestation_report;
use der::asn1::OctetStringRef;
use futures_util::TryStreamExt;
use ic_os_upgrade::api::upgrade_service_server::{UpgradeService, UpgradeServiceServer};
use ic_os_upgrade::api::{
    GetDiskEncryptionKeyRequest, GetDiskEncryptionKeyResponse,
    InitializeGetDiskEncryptionKeyRequest, InitializeGetDiskEncryptionKeyResponse,
};
use ic_os_upgrade::custom_data::GetDiskEncryptionKeyTokenCustomData;
use ic_os_upgrade::registry::get_blessed_guest_launch_measurements_from_registry;
use ic_os_upgrade::{api, DiskEncryptionKeyProvider};
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_local_store::LocalStoreImpl;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use sev::certs::snp::builtin::milan;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::{async_trait, Request, Response, Status};

mod tls;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let attestation_package_generator =
        SevAttestationPackageGenerator::new(CertificateProvider::new(
            // TODO:
            std::path::PathBuf::from("/tmp"),
        ))
        .inspect_err(|err| {
            eprintln!(
                "Failed to initialize attestation package generator, won't return attestation packages: {}",
                err
            );
        })
        .ok();
    let upgrade_service_impl = UpgradeServiceImpl::new(
        attestation_package_generator,
        DiskEncryptionKeyProvider::new()?,
    );

    let tls_acceptor = TlsAcceptor::from(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(include_bytes!(
                    "../../server_cert.pem"
                ))?],
                PrivateKeyDer::from_pem_slice(include_bytes!("../../server_key.pem"))?,
            )?,
    ));

    let tcp_listener =
        TcpListener::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), api::PORT)).await?;
    let stream = TcpListenerStream::new(tcp_listener)
        .and_then(|tcp_stream| tls_acceptor.accept(tcp_stream))
        .map_ok(TlsStreamWrapper);

    println!("Listening on port {}", api::PORT);
    Server::builder()
        .add_service(UpgradeServiceServer::new(upgrade_service_impl))
        .serve_with_incoming(stream)
        .await?;
    Ok(())
}

struct UpgradeServiceInner {
    disk_encryption_key_provider: DiskEncryptionKeyProvider,

    // TODO
    /// If the attestation report cannot be generated, it returns None. While the client will not accept
    /// a None value by default, this still allows us to return the encryption key (and possibly release
    /// a special client which skips attestation verification).
    attestation_package_generator: Option<SevAttestationPackageGenerator>,
}

impl UpgradeServiceInner {
    fn new(
        attestation_package_generator: Option<SevAttestationPackageGenerator>,
        disk_encryption_key_provider: DiskEncryptionKeyProvider,
    ) -> Self {
        Self {
            disk_encryption_key_provider,
            attestation_package_generator,
        }
    }
}

impl UpgradeServiceInner {
    pub fn get_disk_encryption_key(
        &mut self,
        request: Request<GetDiskEncryptionKeyRequest>,
    ) -> Result<Response<GetDiskEncryptionKeyResponse>, Status> {
        let shared_secret = request
            .extensions()
            .get::<TlsConnectionInfoForUpgrade>()
            .ok_or_else(|| Status::internal("CustomConnectionInfo is missing"))?
            .shared_secret;
        let request = request.into_inner();

        let Some(attestation_report) = request.sev_attestation_package else {
            return Err(Status::invalid_argument(
                "sev_attestation_package must not be empty",
            ));
        };

        let attestation_report_custom_data = GetDiskEncryptionKeyTokenCustomData {
            tls_shared_secret: OctetStringRef::new(&shared_secret)
                .expect("Could not encode shared secret"),
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
            key: self
                .disk_encryption_key_provider
                .get_disk_encryption_key()
                .map_err(|e| Status::internal(format!("Failed to get disk encryption key: {}", e)))?
                .into(),
            sev_attestation_package: my_attestation_package,
        }))
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
        &mut self,
        attestation_report_custom_data: &GetDiskEncryptionKeyTokenCustomData,
    ) -> AnyhowResult<SevAttestationPackage> {
        self.attestation_package_generator
            .as_mut()
            .context("Attestation package generator is not available")?
            .generate_attestation_package(attestation_report_custom_data)
            .context("Failed to generate attestation report")
    }
}

struct UpgradeServiceImpl {
    // We can serve a single request at once, but it's not an issue because there is only one
    // client (the upgrade VM).
    inner: Mutex<UpgradeServiceInner>,
}

impl UpgradeServiceImpl {
    pub fn new(
        attestation_package_generator: Option<SevAttestationPackageGenerator>,
        disk_encryption_key_provider: DiskEncryptionKeyProvider,
    ) -> Self {
        Self {
            inner: Mutex::new(UpgradeServiceInner::new(
                attestation_package_generator,
                disk_encryption_key_provider,
            )),
        }
    }
}

#[async_trait]
impl UpgradeService for UpgradeServiceImpl {
    async fn initialize_get_disk_encryption_key(
        &self,
        _: Request<InitializeGetDiskEncryptionKeyRequest>,
    ) -> Result<Response<InitializeGetDiskEncryptionKeyResponse>, Status> {
        Ok(InitializeGetDiskEncryptionKeyResponse::default().into())
    }

    async fn get_disk_encryption_key(
        &self,
        request: Request<GetDiskEncryptionKeyRequest>,
    ) -> Result<Response<GetDiskEncryptionKeyResponse>, Status> {
        self.inner.lock().unwrap().get_disk_encryption_key(request)
    }
}
