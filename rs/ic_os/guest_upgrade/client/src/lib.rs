use crate::tls::SkipServerCertificateCheck;
use anyhow::{Context, Error, Result, anyhow, bail};
use async_trait::async_trait;
use attestation::SevAttestationPackage;
use attestation::attestation_package::{
    AttestationPackageVerifier, ParsedSevAttestationPackage, SevRootCertificateVerification,
};
use config_types::GuestOSConfig;
use der::asn1::OctetStringRef;
use guest_disk::crypt::LuksHeaderLocation;
use guest_upgrade_shared::api::disk_encryption_key_exchange_service_client::DiskEncryptionKeyExchangeServiceClient;
use guest_upgrade_shared::api::{GetDiskEncryptionKeyRequest, SignalStatusRequest};
use guest_upgrade_shared::attestation::GetDiskEncryptionKeyTokenCustomData;
use http::Uri;
use hyper_rustls::{HttpsConnectorBuilder, MaybeHttpsStream};
use hyper_util::rt::TokioIo;
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_pem_file;
use ic_interfaces_registry::RegistryClient;
use ic_protobuf::registry::replica_version::v1::ReplicaVersionRecord;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_client_helpers::replica_version::ReplicaVersionRegistry;
use ic_registry_keys::make_replica_version_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_nns_data_provider_wrappers::CertifiedNnsDataProvider;
use ic_registry_transport::Error as RegistryTransportError;
use ic_types::ReplicaVersion;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use prost::Message;
use rcgen::CertifiedKey;
use rustls::ClientConfig;
use rustls::pki_types::PrivateKeyDer;
use rustls::version::TLS13;
use sev::firmware::guest::AttestationReport;
use sev_guest::attestation_package::generate_attestation_package;
use sev_guest::firmware::SevGuestFirmware;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tonic::transport::{Channel, Endpoint};
use tower::{Service, service_fn};
use url::Url;
use x509_parser::certificate::X509Certificate;
use x509_parser::nom::AsBytes;
use x509_parser::prelude::FromDer;

mod tls;

const NNS_PUBLIC_KEY_PATH: &str = "/run/config/nns_public_key.pem";

/// How long a single update call to the registry may take. The agent's default (6 minutes) is
/// longer than systemd gives the whole key exchange (`guest-upgrade-client.service`).
const REGISTRY_UPDATE_CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// How often to try reading a record from the registry before giving up.
const REGISTRY_UPDATE_CALL_ATTEMPT_COUNT: usize = 3;
const REGISTRY_UPDATE_CALL_RETRY_DELAY: Duration = Duration::from_secs(5);

type ServiceClientType = DiskEncryptionKeyExchangeServiceClient<Channel>;

/// Wrapper around encrypted disk operations to allow testing guest upgrades without setting up
/// block devices which requires root.
#[mockall::automock]
pub trait DiskCryptoOps: Send + Sync {
    /// Returns `Ok(())` if the device can already be unlocked.
    fn can_open(
        &self,
        device_path: &Path,
        luks_header_path: &Path,
        sev_firmware: &mut dyn SevGuestFirmware,
    ) -> Result<()>;

    /// Re-keys the detached LUKS header to the SEV-derived key of the new GuestOS.
    fn rekey(
        &self,
        device_path: &Path,
        luks_header_path: &Path,
        old_key: &[u8],
        sev_firmware: &mut dyn SevGuestFirmware,
    ) -> Result<()>;
}

pub struct DefaultDiskCryptoOps;

impl DiskCryptoOps for DefaultDiskCryptoOps {
    fn can_open(
        &self,
        device_path: &Path,
        luks_header_path: &Path,
        sev_firmware: &mut dyn SevGuestFirmware,
    ) -> Result<()> {
        guest_disk::sev::can_open(
            device_path,
            &LuksHeaderLocation::Detached(luks_header_path.to_path_buf()),
            sev_firmware,
        )
    }

    fn rekey(
        &self,
        device_path: &Path,
        luks_header_path: &Path,
        old_key: &[u8],
        sev_firmware: &mut dyn SevGuestFirmware,
    ) -> Result<()> {
        guest_disk::sev::rekey(
            device_path,
            &LuksHeaderLocation::Detached(luks_header_path.to_path_buf()),
            old_key,
            sev_firmware,
        )
    }
}

/// Source of the launch measurements of elected GuestOS versions, against which the client
/// verifies the server's attestation report.
#[mockall::automock]
#[async_trait]
pub trait ElectedMeasurementsProvider: Send + Sync {
    /// Returns the launch measurements of `guestos_version`. Fails if the version is not elected.
    async fn get_measurements_of_version(
        &self,
        guestos_version: &ReplicaVersion,
    ) -> Result<Vec<Vec<u8>>>;

    /// Returns the launch measurements of all elected GuestOS versions. Only needed for servers
    /// that do not report their GuestOS version yet.
    async fn get_measurements_of_all_versions(&self) -> Result<Vec<Vec<u8>>>;
}

/// Reads launch measurements from the NNS registry.
pub struct NnsElectedMeasurementsProvider {
    nns_urls: Vec<Url>,
    nns_public_key: ThresholdSigPublicKey,
}

impl NnsElectedMeasurementsProvider {
    pub fn new(guestos_config: &GuestOSConfig) -> Result<Self> {
        let nns_public_key = parse_threshold_sig_key_from_pem_file(Path::new(NNS_PUBLIC_KEY_PATH))
            .context("Cannot read NNS public key")?;

        Ok(Self {
            nns_urls: guestos_config.icos_settings.nns_urls.clone(),
            nns_public_key,
        })
    }
}

#[async_trait]
impl ElectedMeasurementsProvider for NnsElectedMeasurementsProvider {
    async fn get_measurements_of_version(
        &self,
        guestos_version: &ReplicaVersion,
    ) -> Result<Vec<Vec<u8>>> {
        // Read the record with an update call: its reply is certified by the NNS subnet, and the
        // agent verifies the certificate against the NNS public key. The certificate only covers
        // this request, so the host, which controls our network, can neither forge nor replay the
        // reply.
        let nns_public_key = self.nns_public_key;
        let registry_canister =
            RegistryCanister::new_with_agent_transformer(self.nns_urls.clone(), |agent| {
                agent
                    .with_nns_public_key(nns_public_key)
                    .with_ingress_timeout(REGISTRY_UPDATE_CALL_TIMEOUT)
            });
        let key = make_replica_version_key(guestos_version).into_bytes();

        let mut attempt = 1;
        let record_bytes = loop {
            let result = registry_canister
                .get_value_with_update(key.clone(), /*version_opt=*/ None)
                .await;
            match result {
                Ok((record_bytes, _registry_version)) => break record_bytes,
                Err(RegistryTransportError::KeyNotPresent(_)) => {
                    bail!("GuestOS version {guestos_version} is not elected")
                }
                Err(err) if attempt < REGISTRY_UPDATE_CALL_ATTEMPT_COUNT => {
                    eprintln!(
                        "Attempt {attempt} to read the record of GuestOS version \
                         {guestos_version} failed, retrying: {err}"
                    );
                    attempt += 1;
                    tokio::time::sleep(REGISTRY_UPDATE_CALL_RETRY_DELAY).await;
                }
                Err(err) => bail!(
                    "Failed to read the record of GuestOS version {guestos_version} from the \
                     registry: {err}"
                ),
            }
        };

        let record = ReplicaVersionRecord::decode(record_bytes.as_slice()).with_context(|| {
            format!("Failed to decode the record of GuestOS version {guestos_version}")
        })?;

        Ok(record
            .guest_launch_measurements
            .unwrap_or_default()
            .guest_launch_measurements
            .into_iter()
            .map(|measurement| measurement.measurement)
            .collect::<Vec<Vec<u8>>>())
    }

    async fn get_measurements_of_all_versions(&self) -> Result<Vec<Vec<u8>>> {
        // Without knowing the server's version, we have to download the whole registry, which
        // can take minutes on nodes far away from the NNS.
        let registry_client = RegistryClientImpl::new(
            Arc::new(CertifiedNnsDataProvider::new(
                tokio::runtime::Handle::current(),
                self.nns_urls.clone(),
                self.nns_public_key,
            )),
            /*metrics_registry=*/ None,
        );
        registry_client.try_polling_latest_version(usize::MAX)?;

        registry_client
            .get_guest_launch_measurements(registry_client.get_latest_version())
            .map_err(|e| anyhow!("Failed to get elected measurements from registry: {e}"))
    }
}

/// Returns the launch measurements to verify the server's attestation report against: those of
/// the GuestOS version the server reports or, if it reports none, those of all elected versions.
///
/// The reported version is not trusted: if the server's attested measurement is not among the
/// measurements of the version it reports, the verification fails.
async fn get_elected_measurements(
    elected_measurements_provider: &dyn ElectedMeasurementsProvider,
    server_guestos_version: Option<&str>,
) -> Result<Vec<Vec<u8>>> {
    // Servers built before they started reporting their GuestOS version.
    let Some(server_guestos_version) = server_guestos_version else {
        println!(
            "Server did not report its GuestOS version, reading the launch measurements of all \
             elected versions"
        );
        return elected_measurements_provider
            .get_measurements_of_all_versions()
            .await;
    };

    let server_guestos_version =
        ReplicaVersion::try_from(server_guestos_version).with_context(|| {
            format!("Server reported an invalid GuestOS version {server_guestos_version:?}")
        })?;
    println!(
        "Server reported GuestOS version {server_guestos_version}, reading its launch measurements"
    );

    elected_measurements_provider
        .get_measurements_of_version(&server_guestos_version)
        .await
}

pub struct DiskEncryptionKeyExchangeClientAgent {
    guestos_config: GuestOSConfig,
    sev_firmware: Box<dyn SevGuestFirmware>,
    elected_measurements_provider: Arc<dyn ElectedMeasurementsProvider>,
    store_device_path: PathBuf,
    store_luks_header_path: PathBuf,
    server_port: u16,
    sev_root_certificate_verification: SevRootCertificateVerification,
    crypto_ops: Arc<dyn DiskCryptoOps>,
}

// Allow 32MB ingress messages - we need 16MB for the LUKS header
const MAX_INCOMING_MESSAGE_SIZE: usize = 32 * 1024 * 1024;

impl DiskEncryptionKeyExchangeClientAgent {
    pub fn new(
        guestos_config: GuestOSConfig,
        sev_root_certificate_verification: SevRootCertificateVerification,
        sev_firmware: Box<dyn SevGuestFirmware>,
        elected_measurements_provider: Arc<dyn ElectedMeasurementsProvider>,
        crypto_ops: Arc<dyn DiskCryptoOps>,
        store_device_path: PathBuf,
        store_luks_header_path: PathBuf,
        server_port: u16,
    ) -> Self {
        DiskEncryptionKeyExchangeClientAgent {
            guestos_config,
            sev_firmware,
            elected_measurements_provider,
            store_device_path,
            store_luks_header_path,
            server_port,
            sev_root_certificate_verification,
            crypto_ops,
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
        let retrieve_status = match self.crypto_ops.can_open(
            &self.store_device_path,
            &self.store_luks_header_path,
            self.sev_firmware.as_mut(),
        ) {
            Ok(()) => {
                println!(
                    "{} can be opened with our derived key, no need to run exchange",
                    self.store_device_path.display()
                );
                Ok(())
            }
            Err(err) => {
                println!("Running the key exchange because the disk cannot be opened: {err:#}");
                self.retrieve_disk_encryption_data(
                    &mut upgrade_service_client,
                    &my_public_key_der,
                    &server_public_key_der,
                )
                .await
                .context("Failed to retrieve disk encryption data")
            }
        };

        let _ignored = upgrade_service_client
            .signal_status(SignalStatusRequest {
                success: Some(retrieve_status.is_ok()),
                debug_info: retrieve_status.as_ref().err().map(|e| format!("{e:?}")),
            })
            .await;

        retrieve_status
    }

    async fn retrieve_disk_encryption_data(
        &mut self,
        upgrade_service_client: &mut ServiceClientType,
        my_public_key_der: &[u8],
        server_public_key_der: &[u8],
    ) -> Result<()> {
        let custom_data = GetDiskEncryptionKeyTokenCustomData {
            client_tls_public_key: OctetStringRef::new(my_public_key_der)
                .expect("Could not encode public key"),
            server_tls_public_key: OctetStringRef::new(server_public_key_der)
                .expect("Could not encode server public key"),
        };
        let my_attestation_package = generate_attestation_package(
            self.sev_firmware.as_mut(),
            self.guestos_config
                .trusted_execution_environment_config
                .as_ref()
                .context("Trusted execution environment config is missing")?,
            &custom_data,
        )
        .context("Failed to generate attestation package")?;

        let my_attestation_report = *my_attestation_package.attestation_report();

        let disk_encryption_data = upgrade_service_client
            .get_disk_encryption_key(GetDiskEncryptionKeyRequest {
                sev_attestation_package: Some(my_attestation_package.into()),
            })
            .await
            .context("Call to get_disk_encryption_key failed")?
            .into_inner();

        let server_attestation_package = disk_encryption_data
            .sev_attestation_package
            .context("Server attestation report is missing")?;

        let elected_measurements = get_elected_measurements(
            self.elected_measurements_provider.as_ref(),
            disk_encryption_data.guestos_version.as_deref(),
        )
        .await?;

        verify_server_attestation_package(
            server_attestation_package,
            &my_attestation_report,
            &custom_data,
            elected_measurements,
            self.sev_root_certificate_verification,
        )
        .context("Failed to verify the server's attestation package")?;

        let disk_encryption_key = disk_encryption_data
            .key
            .context("GetKeyResponse does not contain a key")?;

        let luks_header = disk_encryption_data
            .luks_header
            .context("Server did not send a Store LUKS header")?;

        self.adopt_store_artifacts(disk_encryption_key, luks_header)?;

        Ok(())
    }

    /// Copies the received Store LUKS header to our Var partition and re-keys it: the old
    /// GuestOS's key (received above) is replaced with our own SEV-derived key, which the
    /// default VM we become after the reboot can re-derive.
    fn adopt_store_artifacts(&mut self, old_key: Vec<u8>, luks_header: Vec<u8>) -> Result<()> {
        // Staged next to the final path, so moving it into place stays on the same
        // filesystem. The permissions must allow the orchestrator (running as
        // ic-replica) to read the header.
        let mut staged_header = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o644))
            .tempfile_in(
                self.store_luks_header_path
                    .parent()
                    .context("Store LUKS header path has no parent directory")?,
            )
            .context("Failed to create staged Store LUKS header")?;
        staged_header
            .write_all(&luks_header)
            .context("Failed to write staged Store LUKS header")?;

        self.crypto_ops
            .rekey(
                &self.store_device_path,
                staged_header.path(),
                &old_key,
                self.sev_firmware.as_mut(),
            )
            .context("Failed to re-key the staged Store LUKS header")?;

        staged_header
            .persist(&self.store_luks_header_path)
            .context("Failed to move the staged Store LUKS header into place")?;

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
            DiskEncryptionKeyExchangeServiceClient::new(channel)
                .max_decoding_message_size(MAX_INCOMING_MESSAGE_SIZE),
            server_public_key_der,
        ))
    }
}

pub fn verify_server_attestation_package(
    server_attestation_package: SevAttestationPackage,
    my_attestation_report: &AttestationReport,
    custom_data: &GetDiskEncryptionKeyTokenCustomData<'_>,
    mut elected_measurements: Vec<Vec<u8>>,
    sev_root_certificate_verification: SevRootCertificateVerification,
) -> Result<()> {
    // Our own launch measurement is not eligible: without this check, an attacker
    // occupying the server endpoint could reflect our own attestation package back to us.
    elected_measurements.retain(|measurement| {
        measurement.as_slice() != my_attestation_report.measurement.as_slice()
    });

    ParsedSevAttestationPackage::parse(
        server_attestation_package,
        sev_root_certificate_verification,
    )
    .verify_measurement(&elected_measurements)
    .verify_custom_data(custom_data)
    .verify_chip_id(&[my_attestation_report.chip_id])
    .verify_guest_policy()
    .context("Server attestation report verification failed")?;

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_GUESTOS_VERSION: &str = "server_guestos_version";
    const SERVER_MEASUREMENT: [u8; 48] = [52; 48];

    #[tokio::test]
    async fn test_get_elected_measurements_of_reported_version() {
        let mut provider = MockElectedMeasurementsProvider::new();
        provider
            .expect_get_measurements_of_version()
            .once()
            .withf(|guestos_version| guestos_version.as_ref() == SERVER_GUESTOS_VERSION)
            .returning(|_| Ok(vec![SERVER_MEASUREMENT.to_vec()]));
        provider.expect_get_measurements_of_all_versions().never();

        let measurements = get_elected_measurements(&provider, Some(SERVER_GUESTOS_VERSION))
            .await
            .unwrap();

        assert_eq!(measurements, vec![SERVER_MEASUREMENT.to_vec()]);
    }

    #[tokio::test]
    async fn test_get_elected_measurements_of_all_versions_if_server_reports_no_version() {
        let mut provider = MockElectedMeasurementsProvider::new();
        provider.expect_get_measurements_of_version().never();
        provider
            .expect_get_measurements_of_all_versions()
            .once()
            .returning(|| Ok(vec![SERVER_MEASUREMENT.to_vec()]));

        let measurements = get_elected_measurements(&provider, None).await.unwrap();

        assert_eq!(measurements, vec![SERVER_MEASUREMENT.to_vec()]);
    }

    #[tokio::test]
    async fn test_get_elected_measurements_rejects_invalid_version() {
        let mut provider = MockElectedMeasurementsProvider::new();
        provider.expect_get_measurements_of_version().never();
        provider.expect_get_measurements_of_all_versions().never();

        let error = get_elected_measurements(&provider, Some("../replica_version"))
            .await
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("invalid GuestOS version"),
            "{error:#}"
        );
    }

    /// A server must not be able to make the client fall back to all elected versions by
    /// reporting a version that is not elected.
    #[tokio::test]
    async fn test_get_elected_measurements_does_not_fall_back_if_version_is_not_elected() {
        let mut provider = MockElectedMeasurementsProvider::new();
        provider
            .expect_get_measurements_of_version()
            .once()
            .returning(|guestos_version| bail!("GuestOS version {guestos_version} is not elected"));
        provider.expect_get_measurements_of_all_versions().never();

        let error = get_elected_measurements(&provider, Some(SERVER_GUESTOS_VERSION))
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("not elected"), "{error:#}");
    }
}
