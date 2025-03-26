use crate::api::{
    GetDiskEncryptionKeyRequest, GetDiskEncryptionKeyResponse,
    InitializeGetDiskEncryptionKeyRequest, InitializeGetDiskEncryptionKeyResponse,
};
use api::upgrade_service_server::{UpgradeService, UpgradeServiceServer};
use std::net::Ipv6Addr;
use std::pin::Pin;
// use ic_registry_client_helpers::hostos_version::HostosRegistry;
// use ic_registry_local_registry::LocalRegistry;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
// use rcgen::CertifiedKey;
use futures_util::TryStreamExt;
use ic_os_upgrade::DiskEncryptionKeyProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsStream};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;
use tonic::transport::server::Connected;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{async_trait, Request, Response, Status};

mod api;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let addr = (Ipv6Addr::UNSPECIFIED, 9090); // TODO: load port from config
                                              //
                                              // let CertifiedKey { cert, key_pair } =
                                              //     rcgen::generate_simple_self_signed(["localhost".to_string()])?;
                                              //
                                              // let cert_pem = cert.pem();
                                              // let key_pem = key_pair.serialize_pem();
    let cert_pem = "-----BEGIN CERTIFICATE-----
MIIBXjCCAQSgAwIBAgIUDFYwDNWiIceB0Wb5tiJGecNFF/YwCgYIKoZIzj0EAwIw
ITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDAgFw03NTAxMDEwMDAw
MDBaGA80MDk2MDEwMTAwMDAwMFowITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWdu
ZWQgY2VydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEPo88fsQjowF9hSjfKq
sBntsNc9VWTimq06sEQFeFKhIqVX1ktwrCutZ9XdGXfcCdw18xx5Ude5zKjbfmTF
M/qjGDAWMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQDAgNIADBFAiEA
6n0/QyPwVmzvaBfE4FD/RP80V2SucIB41Vcn/TWj2jkCIFyib/viOb14iuQevybZ
w8hP234LI8XvDq/1md9dVa1n
-----END CERTIFICATE-----";

    let key_pem = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIL/av5lEbQbtdw27
MqI2/iiYoMSMADqtN0yODPKIRKGhRANCAARD6PPH7EI6MBfYUo3yqrAZ7bDXPVVk
4pqtOrBEBXhSoSKlV9ZLcKwrrWfV3Rl33AncNfMceVHXucyo235kxTP6
-----END PRIVATE KEY-----";
    println!("{}", cert_pem);
    println!("{}", key_pem);

    rustls::crypto::ring::default_provider().install_default();

    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap()],
                PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap(),
            )
            .unwrap(),
    );

    let tls_acceptor = TlsAcceptor::from(server_config);
    let tcp_listener = TcpListener::bind(addr).await?;
    let tls_stream =
        TcpListenerStream::new(tcp_listener).and_then(|conn| tls_acceptor.accept(conn));

    Server::builder()
        .add_service(UpgradeServiceServer::new(UpgradeServiceImpl::default()))
        .serve_with_incoming(tls_stream)
        .await?;
    Ok(())
}

type Nonce = [u8; 32];
struct UpgradeServiceInner {
    nonce: Option<Nonce>,
    random: StdRng,
    key_provider: DiskEncryptionKeyProvider,
}

impl Default for UpgradeServiceInner {
    fn default() -> Self {
        Self {
            nonce: None,
            random: StdRng::from_entropy(),
            key_provider: DiskEncryptionKeyProvider {},
        }
    }
}

impl UpgradeServiceImpl {
    pub fn verify_set_disk_encryption_key_request(
        request: &GetDiskEncryptionKeyRequest,
        expected_nonce: &[u8],
    ) -> Result<(), String> {
        //     // verify_sev_attestation_report_signature(&request.sev_attestation_report)?;
        //
        //     if request.nonce != expected_nonce {
        //         return Err(VerificationErrorDetail::InvalidNonce {}.into());
        //     }
        //
        //     let expected_custom_data = GetDiskEncryptionKeyCustomData {
        //         nonce: OctetStringRef::new(&request.nonce).map_err(VerificationError::internal)?,
        //         tls_public_key: OctetStringRef::new(&request.tls_public_key_der)
        //             .map_err(VerificationError::internal)?,
        //     }
        //         .to_bytes()
        //         .map_err(VerificationError::internal)?;
        //     let attestation_report =
        //         as_attestation_report(&request.sev_attestation_report.attestation_report)?;
        //     let actual_custom_data = attestation_report.report_data;
        //     if actual_custom_data != expected_custom_data {
        //         return Err(VerificationErrorDetail::InvalidAttestationReport {
        //             message: format!(
        //                 "Expected attestation report custom data: {expected_custom_data:?}, \
        //              actual: {actual_custom_data:?}"
        //             ),
        //         }
        //             .into());
        //     }

        Ok(())
    }
}

impl UpgradeServiceInner {
    pub fn get_disk_encryption_key(
        &mut self,
        request: Request<GetDiskEncryptionKeyRequest>,
    ) -> Result<Response<GetDiskEncryptionKeyResponse>, Status> {
        // let registry =
        //     LocalRegistry::new("/var/opt/registry/store", Duration::from_secs(30)).unwrap();

        // let versions = registry.get_hostos_versions(registry.get_latest_version())?;

        // dbg!(versions);

        let Some(ref expected_nonce) = self.nonce else {
            return Err(Status::failed_precondition(
                "InitializeGetDiskEncryptionKey must be called first",
            ));
        };

        let Some(ref attestation_report) = request.get_ref().sev_attestation_report else {
            return Err(Status::invalid_argument(
                "sev_attestation_report must not be empty",
            ));
        };

        // set luks encryption key from key

        Ok(Response::new(GetDiskEncryptionKeyResponse {}))
    }

    pub fn initialize_get_disk_encryption_key(
        &mut self,
        request: Request<InitializeGetDiskEncryptionKeyRequest>,
    ) -> Result<Response<InitializeGetDiskEncryptionKeyResponse>, Status> {
        let mut nonce = [0; 32];
        self.random.fill_bytes(&mut nonce);
        self.nonce = Some(nonce);

        Ok(Response::new(InitializeGetDiskEncryptionKeyResponse {
            nonce: Some(nonce.to_vec()),
        }))
    }
}

#[derive(Default)]
struct UpgradeServiceImpl {
    // We can serve a single request at once, but it's not an issue because there is only one
    // client (the other VM).
    inner: Mutex<UpgradeServiceInner>,
}

#[async_trait]
impl UpgradeService for UpgradeServiceImpl {
    async fn get_disk_encryption_key(
        &self,
        request: Request<GetDiskEncryptionKeyRequest>,
    ) -> Result<Response<GetDiskEncryptionKeyResponse>, Status> {
        self.inner.lock().unwrap().set_disk_encryption_key(request)
    }

    async fn initialize_get_disk_encryption_key(
        &self,
        request: Request<InitializeGetDiskEncryptionKeyRequest>,
    ) -> Result<Response<InitializeGetDiskEncryptionKeyResponse>, Status> {
        self.inner
            .lock()
            .unwrap()
            .initialize_set_disk_encryption_key(request)
    }
}
