use crate::SevFirmwareFactory;
use crate::server::ConnInfo;
use attestation::attestation_package::generate_attestation_package;
use attestation::custom_data::DerEncodedCustomData;
use attestation::verification::{SevRootCertificateVerification, verify_attestation_package};
use config_types::TrustedExecutionEnvironmentConfig;
use der::asn1::OctetStringRef;
use guest_upgrade_shared::api::{
    GetDiskEncryptionKeyRequest, GetDiskEncryptionKeyResponse, SignalStatusRequest,
    SignalStatusResponse,
    disk_encryption_key_exchange_service_server::DiskEncryptionKeyExchangeService,
};
use guest_upgrade_shared::attestation::GetDiskEncryptionKeyTokenCustomData;
use ic_sev::guest::key_deriver::{Key, derive_key_from_sev_measurement};
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use std::ops::Deref;
use std::path::Path;
use tokio::sync::watch::Sender;
use tonic::{Request, Response, Status, async_trait};
use x509_parser::nom::AsBytes;
use x509_parser::parse_x509_certificate;

pub struct DiskEncryptionKeyExchangeServiceImpl {
    sev_firmware_factory: SevFirmwareFactory,
    trusted_execution_environment_config: TrustedExecutionEnvironmentConfig,
    my_public_key: Vec<u8>,
    status_sender: Sender<Result<(), String>>,
    blessed_measurements: Vec<Vec<u8>>,
    sev_root_certificate_verification: SevRootCertificateVerification,
}

impl DiskEncryptionKeyExchangeServiceImpl {
    pub fn new(
        sev_firmware_factory: SevFirmwareFactory,
        sev_root_certificate_verification: SevRootCertificateVerification,
        my_public_key: Vec<u8>,
        trusted_execution_environment_config: TrustedExecutionEnvironmentConfig,
        status_sender: Sender<Result<(), String>>,
        blessed_measurements: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            sev_firmware_factory,
            my_public_key,
            trusted_execution_environment_config,
            status_sender,
            blessed_measurements,
            sev_root_certificate_verification,
        }
    }

    // Return the client's public key in DER format.
    #[allow(clippy::result_large_err)]
    fn client_public_key_from_request(
        request: &Request<GetDiskEncryptionKeyRequest>,
    ) -> Result<Vec<u8>, Status> {
        let certificates = &request
            .extensions()
            .get::<ConnInfo>()
            .ok_or_else(|| Status::internal("TlsConnectInfo is missing"))?
            .certificates;

        if certificates.is_empty() {
            return Err(Status::invalid_argument(
                "Expected at least one TLS certificate".to_string(),
            ));
        }

        let cert = parse_x509_certificate(certificates[0].as_bytes()).map_err(|e| {
            Status::invalid_argument(format!("Failed to parse TLS certificate: {e}"))
        })?;

        Ok(cert.1.public_key().raw.to_vec())
    }
}

#[async_trait]
impl DiskEncryptionKeyExchangeService for DiskEncryptionKeyExchangeServiceImpl {
    async fn get_disk_encryption_key(
        &self,
        request: Request<GetDiskEncryptionKeyRequest>,
    ) -> Result<Response<GetDiskEncryptionKeyResponse>, Status> {
        let result = self.get_disk_encryption_key_impl(request).await;
        if let Err(e) = result.as_ref() {
            eprintln!("get_disk_encryption_key returned error: {}", e.message());
        }
        result
    }

    async fn signal_status(
        &self,
        request: Request<SignalStatusRequest>,
    ) -> Result<Response<SignalStatusResponse>, Status> {
        self.signal_status_impl(request).await
    }
}

impl DiskEncryptionKeyExchangeServiceImpl {
    async fn get_disk_encryption_key_impl(
        &self,
        request: Request<GetDiskEncryptionKeyRequest>,
    ) -> Result<Response<GetDiskEncryptionKeyResponse>, Status> {
        let Some(client_attestation_package) = &request.get_ref().sev_attestation_package else {
            return Err(Status::invalid_argument(
                "sev_attestation_package must not be empty",
            ));
        };

        let mut sev_firmware = self.sev_firmware_factory.deref()()
            .map_err(|e| Status::internal(format!("Failed to create SEV firmware: {e:?}")))?;

        let client_public_key = Self::client_public_key_from_request(&request)?;

        let custom_data = DerEncodedCustomData(GetDiskEncryptionKeyTokenCustomData {
            client_tls_public_key: OctetStringRef::new(&client_public_key)
                .expect("Could not encode client public key"),
            server_tls_public_key: OctetStringRef::new(&self.my_public_key)
                .expect("Could not encode server public key"),
        });

        let my_attestation_package = generate_attestation_package(
            sev_firmware.as_mut(),
            &self.trusted_execution_environment_config,
            &custom_data,
        )
        .map_err(|e| Status::internal(format!("Failed to generate attestation package: {e:?}")))?;

        let my_attestation_report = AttestationReport::from_bytes(
            my_attestation_package
                .attestation_report
                .as_ref()
                .expect("Expected attestation report to be present"),
        )
        .map_err(|e| Status::internal(format!("Failed to parse own attestation report: {e:?}")))?;

        verify_attestation_package(
            client_attestation_package,
            self.sev_root_certificate_verification,
            &self.blessed_measurements,
            &custom_data,
            Some(my_attestation_report.chip_id.as_slice()),
        )
        .map_err(|e| {
            Status::invalid_argument(format!("Attestation report verification failed: {e:?}"))
        })?;

        let mut sev_firmware = self.sev_firmware_factory.deref()()
            .map_err(|e| Status::internal(format!("Failed to create SEV firmware: {e:?}")))?;

        Ok(Response::new(GetDiskEncryptionKeyResponse {
            key: Some(
                derive_key_from_sev_measurement(
                    sev_firmware.as_mut(),
                    Key::DiskEncryptionKey {
                        device_path: Path::new("/dev/vda10"),
                    },
                )
                .map_err(|e| Status::internal(format!("Failed to get disk encryption key: {e:?}")))?
                .into_bytes(),
            ),
            sev_attestation_package: Some(my_attestation_package),
        }))
    }

    async fn signal_status_impl(
        &self,
        request: Request<SignalStatusRequest>,
    ) -> Result<Response<SignalStatusResponse>, Status> {
        let debug_info = request
            .get_ref()
            .debug_info
            .as_deref()
            .unwrap_or("No debug info.");
        match request.get_ref().success {
            Some(true) => {
                let _ = self.status_sender.send(Ok(()));
            }
            Some(false) => {
                let _ = self.status_sender.send(Err(format!(
                    "Upgrade failed. Debug info from Upgrade VM: {debug_info}"
                )));
            }
            None => {
                let _ = self.status_sender.send(Err(format!(
                    "No status in SignalStatusRequest. Debug info from Upgrade VM: {debug_info}"
                )));
            }
        }

        Ok(Response::new(SignalStatusResponse {}))
    }
}
