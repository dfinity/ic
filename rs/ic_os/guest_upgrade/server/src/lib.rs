use crate::service::DiskEncryptionKeyExchangeServiceImpl;
use attestation::registry::get_blessed_guest_launch_measurements_from_registry;
use attestation::verification::SevRootCertificateVerification;
use config_types::TrustedExecutionEnvironmentConfig;
use guest_upgrade_shared::DEFAULT_SERVER_PORT;
use ic_interfaces_registry::RegistryClient;
use ic_sev::guest::firmware::SevGuestFirmware;
use server::DiskEncryptionKeyExchangeServer;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::sync::watch;
use vsock_lib::VSockClient;
use vsock_lib::protocol::Command;

pub mod orchestrator;
mod server;
mod service;
mod tls;

pub type SevFirmwareFactory =
    Arc<dyn Fn() -> anyhow::Result<Box<dyn SevGuestFirmware>> + Send + Sync>;

const DEFAULT_SUCCESS_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Error, Debug)]
pub enum DiskEncryptionKeyExchangeError {
    #[error("Server start error: {0}")]
    ServerStartError(String),
    #[error("UpgradeVM error: {0}")]
    UpgradeVmError(String),
}

pub struct DiskEncryptionKeyExchangeServerAgent {
    runtime_handle: Handle,
    sev_firmware_factory: SevFirmwareFactory,
    sev_root_certificate_verification: SevRootCertificateVerification,
    trusted_execution_environment_config: TrustedExecutionEnvironmentConfig,
    vsock_client: Box<dyn VSockClient + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    port: u16,
    success_timeout: Duration,
}

impl DiskEncryptionKeyExchangeServerAgent {
    pub fn new(
        handle: Handle,
        vsock_client: Box<dyn VSockClient + Send + Sync>,
        sev_firmware_factory: SevFirmwareFactory,
        trusted_execution_environment_config: TrustedExecutionEnvironmentConfig,
        registry_client: Arc<dyn RegistryClient>,
    ) -> Self {
        Self {
            runtime_handle: handle,
            vsock_client,
            sev_firmware_factory,
            sev_root_certificate_verification: SevRootCertificateVerification::Verify,
            trusted_execution_environment_config,
            registry_client,
            port: DEFAULT_SERVER_PORT,
            success_timeout: DEFAULT_SUCCESS_TIMEOUT,
        }
    }

    pub fn new_for_testing(
        handle: Handle,
        vsock_client: Box<dyn VSockClient + Send + Sync>,
        sev_firmware_factory: SevFirmwareFactory,
        sev_root_certificate_verification: SevRootCertificateVerification,
        trusted_execution_environment_config: TrustedExecutionEnvironmentConfig,
        registry_client: Arc<dyn RegistryClient>,
        port: u16,
        success_timeout: Duration,
    ) -> Self {
        Self {
            runtime_handle: handle,
            vsock_client,
            sev_firmware_factory,
            sev_root_certificate_verification,
            trusted_execution_environment_config,
            registry_client,
            port,
            success_timeout,
        }
    }

    pub async fn exchange_keys(&self) -> Result<(), DiskEncryptionKeyExchangeError> {
        // Channel to communicate the success status of the key exchange.
        let (status_sender, mut status_receiver) = watch::channel(Ok(()));

        let certified_key =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(|err| {
                DiskEncryptionKeyExchangeError::ServerStartError(format!(
                    "Failed to generate self-signed certificate: {err}"
                ))
            })?;

        let blessed_measurements = get_blessed_guest_launch_measurements_from_registry(
            &*self.registry_client,
        )
        .map_err(|err| {
            DiskEncryptionKeyExchangeError::ServerStartError(format!(
                "Failed to get blessed measurements: {err}"
            ))
        })?;
        let upgrade_service = Arc::new(DiskEncryptionKeyExchangeServiceImpl::new(
            self.sev_firmware_factory.clone(),
            self.sev_root_certificate_verification,
            certified_key.key_pair.public_key_der(),
            self.trusted_execution_environment_config.clone(),
            status_sender,
            blessed_measurements,
        ));

        // Start the server that the Upgrade VM can connect to for getting the keys.
        // Assign it to a variable to keep the server alive until the function returns.
        let _server = DiskEncryptionKeyExchangeServer::start_new(
            self.runtime_handle.clone(),
            self.port,
            certified_key,
            upgrade_service,
        )
        .await
        .map_err(|err| DiskEncryptionKeyExchangeError::ServerStartError(err.to_string()))?;

        // Tell the host to start the Upgrade VM.
        self.vsock_client
            .send_command(Command::StartUpgradeGuestVM)
            .map_err(|err| DiskEncryptionKeyExchangeError::UpgradeVmError(err.to_string()))?;

        // Wait for status.
        match tokio::time::timeout(self.success_timeout, status_receiver.changed()).await {
            Ok(Ok(_)) => status_receiver.borrow_and_update().clone().map_err(|err| {
                DiskEncryptionKeyExchangeError::UpgradeVmError(format!(
                    "Upgrade VM failed to complete key exchange. {err}"
                ))
            }),
            Ok(Err(err)) => Err(DiskEncryptionKeyExchangeError::UpgradeVmError(format!(
                "Failed to receive key exchange completion: {err}"
            ))),
            Err(_) => Err(DiskEncryptionKeyExchangeError::UpgradeVmError(format!(
                "Timeout waiting for disk encryption key exchange to complete after {:?}",
                self.success_timeout
            ))),
        }
    }
}
