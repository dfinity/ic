use anyhow::Context;
use attestation::custom_data::{SevCustomData, SevCustomDataNamespace};
use config_tool::{DEFAULT_GUESTOS_CONFIG_OBJECT_PATH, deserialize_config};
use config_types::GuestOSConfig;
use config_types::TrustedExecutionEnvironmentConfig;
use remote_attestation_shared::DEFAULT_PORT;
use remote_attestation_shared::proto::remote_attestation_service_server::{
    RemoteAttestationService, RemoteAttestationServiceServer,
};
use remote_attestation_shared::proto::{AttestRequest, AttestResponse};
use sev::firmware::guest::Firmware;
use sev_guest::attestation_package::generate_attestation_package;
use sev_guest::firmware::SevGuestFirmware;
use sev_guest::is_sev_active;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

enum RemoteAttestationServiceImpl {
    SevEnabled {
        firmware: Arc<Mutex<Box<dyn SevGuestFirmware + Send>>>,
        trusted_execution_config: TrustedExecutionEnvironmentConfig,
    },
    SevDisabled,
}

impl RemoteAttestationServiceImpl {
    pub fn new(
        firmware: Box<dyn SevGuestFirmware + Send>,
        tee_config: TrustedExecutionEnvironmentConfig,
    ) -> Self {
        Self::SevEnabled {
            firmware: Arc::new(Mutex::new(firmware)),
            trusted_execution_config: tee_config,
        }
    }

    #[allow(clippy::result_large_err)]
    fn sev_custom_data_from_request(&self, req: &AttestRequest) -> Result<SevCustomData, Status> {
        let custom_data: [u8; 32] = match &req.custom_data {
            Some(bytes) => bytes
                .as_slice()
                .try_into()
                .map_err(|_| Status::invalid_argument("custom_data must be 32 bytes"))?,
            None => [0; 32],
        };

        Ok(SevCustomData::new(
            SevCustomDataNamespace::RawRemoteAttestation,
            custom_data,
        ))
    }
}

#[tonic::async_trait]
impl RemoteAttestationService for RemoteAttestationServiceImpl {
    async fn attest(
        &self,
        request: Request<AttestRequest>,
    ) -> Result<Response<AttestResponse>, Status> {
        let req = request.into_inner();
        let custom_data = self.sev_custom_data_from_request(&req)?;

        let RemoteAttestationServiceImpl::SevEnabled {
            firmware,
            trusted_execution_config,
        } = self
        else {
            return Err(Status::unavailable("SEV is not enabled on this node"));
        };

        let mut guard = firmware.lock().expect("Failed to lock firmware mutex");
        let attestation_package =
            generate_attestation_package(guard.as_mut(), trusted_execution_config, &custom_data)
                .map_err(|e| {
                    Status::internal(format!("failed to generate attestation package: {e}"))
                })?;

        Ok(Response::new(AttestResponse {
            attestation_package: Some(attestation_package.into()),
        }))
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service_impl = if is_sev_active()? {
        let guestos_config: GuestOSConfig = deserialize_config(DEFAULT_GUESTOS_CONFIG_OBJECT_PATH)
            .context("Failed to read GuestOS config")?;

        let trusted_execution_config = guestos_config
            .trusted_execution_environment_config
            .ok_or_else(|| {
                anyhow::anyhow!("TrustedExecutionEnvironmentConfig missing in GuestOS config")
            })?;

        let firmware = Firmware::open().context("Failed to open /dev/sev-guest")?;

        RemoteAttestationServiceImpl::new(Box::new(firmware), trusted_execution_config)
    } else {
        eprintln!("SEV is not active. Remote attestation service will return errors.");
        RemoteAttestationServiceImpl::SevDisabled
    };

    Server::builder()
        .add_service(RemoteAttestationServiceServer::new(service_impl))
        .serve(SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            DEFAULT_PORT,
        ))
        .await?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("remote_attestation_server can only run on Linux (requires /dev/sev-guest).");
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestation::attestation_package::{
        AttestationPackageVerifier, ParsedSevAttestationPackage, SevRootCertificateVerification,
    };
    use rand::SeedableRng;
    use rand::rngs::SmallRng;
    use sev_guest_testing::{FakeAttestationReportSigner, MockSevGuestFirmwareBuilder};
    use tokio::test;

    async fn attest_and_get_report(
        request: AttestRequest,
    ) -> Result<ParsedSevAttestationPackage, Status> {
        let signer = FakeAttestationReportSigner::default();
        let service = RemoteAttestationServiceImpl::SevEnabled {
            firmware: Arc::new(Mutex::new(Box::new(
                MockSevGuestFirmwareBuilder::new().with_signer(Some(signer.clone())),
            ))),
            trusted_execution_config: TrustedExecutionEnvironmentConfig {
                sev_cert_chain_pem: signer.get_certificate_chain_pem(),
            },
        };
        let response = service.attest(Request::new(request)).await?;
        let attestation_package = response
            .into_inner()
            .attestation_package
            .expect("No attestation package");

        Ok(ParsedSevAttestationPackage::parse(
            attestation_package,
            SevRootCertificateVerification::TestOnlySkipVerification,
        )
        .expect("Failed to parse attestation package"))
    }

    #[test]
    async fn test_empty_attest_request_works() {
        let request = AttestRequest { custom_data: None };

        let attestation_report = attest_and_get_report(request).await.unwrap();
        attestation_report
            .verify_custom_data(&SevCustomData::new(
                SevCustomDataNamespace::RawRemoteAttestation,
                [0u8; 32],
            ))
            .unwrap();
    }

    #[test]
    async fn test_31_bytes_fails() {
        let custom_data = [0u8; 31];
        let request = AttestRequest {
            custom_data: Some(custom_data.to_vec()),
        };

        let err = attest_and_get_report(request)
            .await
            .expect_err("Expected error");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("32 bytes"));
    }

    #[test]
    async fn test_correct_namespace_works() {
        let custom_data = SevCustomData::random(
            SevCustomDataNamespace::RawRemoteAttestation,
            &mut SmallRng::seed_from_u64(42),
        );
        let request = AttestRequest {
            custom_data: Some(custom_data.data.to_vec()),
        };

        let attestation_report = attest_and_get_report(request).await.unwrap();
        attestation_report.verify_custom_data(&custom_data).unwrap();
    }
}
