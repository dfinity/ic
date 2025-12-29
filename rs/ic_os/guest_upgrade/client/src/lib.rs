use crate::tls::SkipServerCertificateCheck;
use anyhow::{Context, Error, Result, anyhow, bail};
use attestation::attestation_package::generate_attestation_package;
use attestation::custom_data::DerEncodedCustomData;
use attestation::registry::get_blessed_guest_launch_measurements_from_registry;
use attestation::verification::{SevRootCertificateVerification, verify_attestation_package};
use config_types::GuestOSConfig;
use der::asn1::OctetStringRef;
use guest_upgrade_shared::api::disk_encryption_key_exchange_service_client::DiskEncryptionKeyExchangeServiceClient;
use guest_upgrade_shared::api::{GetDiskEncryptionKeyRequest, SignalStatusRequest};
use guest_upgrade_shared::attestation::GetDiskEncryptionKeyTokenCustomData;
use http::Uri;
use hyper_rustls::{HttpsConnectorBuilder, MaybeHttpsStream};
use hyper_util::rt::TokioIo;
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_pem_file;
use ic_interfaces_registry::RegistryClient;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_nns_data_provider_wrappers::CertifiedNnsDataProvider;
use ic_sev::guest::firmware::SevGuestFirmware;
use rcgen::CertifiedKey;
use rustls::ClientConfig;
use rustls::pki_types::PrivateKeyDer;
use rustls::version::TLS13;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpStream;
use tonic::transport::{Channel, Endpoint};
use tower::{Service, service_fn};
use x509_parser::certificate::X509Certificate;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::FromDer;

mod tls;

const NNS_PUBLIC_KEY_PATH: &str = "/run/config/nns_public_key.pem";

type ServiceClientType = DiskEncryptionKeyExchangeServiceClient<Channel>;
pub type CanOpenStore =
    Box<dyn Fn(&Path, &Path, &mut dyn SevGuestFirmware) -> Result<bool> + Send + Sync>;

pub struct DiskEncryptionKeyExchangeClientAgent {
    guestos_config: GuestOSConfig,
    sev_firmware: Box<dyn SevGuestFirmware>,
    nns_registry_client: Arc<dyn RegistryClient>,
    previous_key_path: PathBuf,
    server_port: u16,
    sev_root_certificate_verification: SevRootCertificateVerification,
    // We mock can_open_store for easier testing, in production it calls
    // guest_disk::sev::can_open_store, the signature corresponds to that function
    can_open_store: CanOpenStore,
}

impl DiskEncryptionKeyExchangeClientAgent {
    pub fn new(
        guestos_config: GuestOSConfig,
        sev_root_certificate_verification: SevRootCertificateVerification,
        sev_firmware: Box<dyn SevGuestFirmware>,
        nns_registry_client: Arc<dyn RegistryClient>,
        can_open_store: CanOpenStore,
        previous_key_path: PathBuf,
        server_port: u16,
    ) -> Self {
        DiskEncryptionKeyExchangeClientAgent {
            guestos_config,
            sev_firmware,
            nns_registry_client,
            previous_key_path,
            server_port,
            sev_root_certificate_verification,
            can_open_store,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        let peer_guest_vm_address = self
            .guestos_config
            .upgrade_config
            .peer_guest_vm_address
            .context("Peer guest VM address is not set in the GuestOS config")?;

        let my_certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .context("Failed to generate self-signed certificate")?;

        let my_public_key_der = my_certificate.key_pair.public_key_der().clone();

        let server_uri = Uri::from_maybe_shared(format!(
            "https://[{}]:{}",
            peer_guest_vm_address, self.server_port
        ))
        .context("Could not parse URL")?;
        println!("Connecting to server at {server_uri}");
        let (mut upgrade_service_client, server_public_key_der) = self
            .create_upgrade_service_client(server_uri.clone(), my_certificate)
            .await
            .context(format!("Could not connect to server at {server_uri}"))?;
        println!("Connected successfully to server");

        // If we can already open the store, we don't need to run the key exchange.
        // (We still have to call signal_status, since the server is expecting us to signal
        // success)
        let can_open_store = (self.can_open_store)(
            Path::new("/dev/vda10"),
            &self.previous_key_path,
            self.sev_firmware.as_mut(),
        )?;

        let retrieve_status = if can_open_store {
            println!("/dev/vda10 can be opened with our derived key, no need to run exchange");
            Ok(())
        } else {
            self.retrieve_disk_encryption_key(
                &mut upgrade_service_client,
                &my_public_key_der,
                &server_public_key_der,
            )
            .await
            .context("Failed to retrieve disk encryption key")
        };

        let _ignored = upgrade_service_client
            .signal_status(SignalStatusRequest {
                success: Some(retrieve_status.is_ok()),
                debug_info: retrieve_status.as_ref().err().map(|e| format!("{e:?}")),
            })
            .await;

        retrieve_status
    }

    async fn retrieve_disk_encryption_key(
        &mut self,
        upgrade_service_client: &mut ServiceClientType,
        my_public_key_der: &[u8],
        server_public_key_der: &[u8],
    ) -> Result<()> {
        let custom_data = DerEncodedCustomData(GetDiskEncryptionKeyTokenCustomData {
            client_tls_public_key: OctetStringRef::new(my_public_key_der)
                .expect("Could not encode public key"),
            server_tls_public_key: OctetStringRef::new(server_public_key_der)
                .expect("Could not encode server public key"),
        });
        let my_attestation_package = generate_attestation_package(
            self.sev_firmware.as_mut(),
            self.guestos_config
                .trusted_execution_environment_config
                .as_ref()
                .context("Trusted execution environment config is missing")?,
            &custom_data,
        )
        .context("Failed to generate attestation package")?;

        let my_attestation_report = AttestationReport::from_bytes(
            my_attestation_package
                .attestation_report
                .as_ref()
                .context("My attestation report is missing")?,
        )
        .context("Failed to parse my attestation report")?;

        let get_key_response = upgrade_service_client
            .get_disk_encryption_key(GetDiskEncryptionKeyRequest {
                sev_attestation_package: Some(my_attestation_package),
            })
            .await
            .context("Call to get_disk_encryption_key failed")?
            .into_inner();

        let server_attestation_package = get_key_response
            .sev_attestation_package
            .context("Server attestation report is missing")?;

        let blessed_measurements =
            get_blessed_guest_launch_measurements_from_registry(&*self.nns_registry_client)
                .map_err(|e| anyhow!("Failed to get blessed measurements from registry: {e}"))?;

        // Verify the server's attestation report. This is to ensure that the key comes from a
        // trusted source. Without this check, an attacker could start with a malicious GuestOS,
        // inject malicious files into the data partition then trigger an upgrade to a
        // legit version. The malicious data would remain on the data partition.
        verify_attestation_package(
            &server_attestation_package,
            self.sev_root_certificate_verification,
            &blessed_measurements,
            &custom_data,
            Some(my_attestation_report.chip_id.as_ref()),
        )
        .context("Server attestation report verification failed")?;

        let disk_encryption_key = get_key_response
            .key
            .context("GetKeyResponse does not contain a key")?;

        let disk_encryption_key =
            String::from_utf8(disk_encryption_key).context("Key is not valid UTF-8")?;

        std::fs::write(&*self.previous_key_path, disk_encryption_key).with_context(|| {
            format!(
                "Failed to write key to {}",
                self.previous_key_path.display()
            )
        })?;

        Ok(())
    }

    async fn create_upgrade_service_client(
        &self,
        server_addr: Uri,
        my_certified_key: CertifiedKey,
    ) -> Result<(ServiceClientType, Vec<u8>)> {
        let cert_der = my_certified_key.cert.der().clone();
        let key_der = PrivateKeyDer::try_from(my_certified_key.key_pair.serialize_der())
            .map_err(|e| anyhow!("{e}"))
            .context("Failed to convert private key")?;

        // Create TLS client configuration with custom certificate verifier
        let client_config = ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerCertificateCheck))
            .with_client_auth_cert(vec![cert_der], key_der)
            .context("Failed to configure client authentication")?;

        let mut connector = HttpsConnectorBuilder::new()
            .with_tls_config(client_config)
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();

        // The following part of the code is somewhat hacky, but it is needed to
        // extract the server's public key from the TLS connection.
        // By default, when the connector creates a new TLS connection, the channel does not expose
        // the connection object, which contains the server's certificate.
        // So we instead create the connection first, extract the server's public key,
        // and then pass the connection to the connector to return it when the client needs it.
        let connection = connector
            .call(server_addr)
            .await
            .map_err(Error::from_boxed)
            .context("Could not connect")?;

        let server_public_key_der = extract_server_public_key_der(&connection)?;
        let mut connection = Some(connection);
        let connector = service_fn(move |_uri: Uri| {
            let connection = connection.take();
            async move { connection.context("Connection already taken") }
        });

        // Note that we already have a connection so we just use a dummy endpoint.
        let channel = Endpoint::from_static("http://_")
            .connect_with_connector(connector)
            .await
            .context("Failed to connect to server")?;

        Ok((
            DiskEncryptionKeyExchangeServiceClient::new(channel),
            server_public_key_der,
        ))
    }
}

fn extract_server_public_key_der(conn: &MaybeHttpsStream<TokioIo<TcpStream>>) -> Result<Vec<u8>> {
    let MaybeHttpsStream::Https(https) = conn else {
        bail!("Expected an HTTPS connection");
    };

    let peer_certificates = https
        .inner()
        .get_ref()
        .1
        .peer_certificates()
        .ok_or_else(|| anyhow!("No peer certificates found"))?;

    if peer_certificates.is_empty() {
        return Err(anyhow!("No server certificate provided"));
    }

    let public_key_der = X509Certificate::from_der(
        peer_certificates
            .first()
            .context("No server certs provided")?
            .as_bytes(),
    )
    .context("Failed to parse server certificate")?
    .1
    .public_key()
    .raw
    .to_vec();

    Ok(public_key_der)
}

pub fn create_nns_registry_client(guestos_config: &GuestOSConfig) -> Result<RegistryClientImpl> {
    let nns_public_key = parse_threshold_sig_key_from_pem_file(Path::new(NNS_PUBLIC_KEY_PATH))
        .context("Cannot read NNS public key")?;

    let client = RegistryClientImpl::new(
        Arc::new(CertifiedNnsDataProvider::new(
            tokio::runtime::Handle::current(),
            guestos_config.icos_settings.nns_urls.clone(),
            nns_public_key,
        )),
        /*metrics_registry=*/ None,
    );
    client.try_polling_latest_version(usize::MAX)?;

    Ok(client)
}
