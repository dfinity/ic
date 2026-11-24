use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::service::{DiskEncryptionKeyExchangeServiceImpl, ElectedGuestOsVersion};
use attestation::attestation_package::SevRootCertificateVerification;
use config_types::TrustedExecutionEnvironmentConfig;
use ic_interfaces_registry::RegistryClient;
use ic_registry_client_helpers::replica_version::ReplicaVersionRegistry;
use ic_types::ReplicaVersion;
use server::DiskEncryptionKeyExchangeServer;
use sev_guest::firmware::SevGuestFirmware;
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::sync::watch;
use vsock_lib::client::VsockClient;
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
    vsock_client: Box<dyn VsockClient + Send + Sync>,
    registry_client: Arc<dyn RegistryClient>,
    store_device_path: PathBuf,
    store_luks_header_path: PathBuf,
    port: u16,
    success_timeout: Duration,
}

impl DiskEncryptionKeyExchangeServerAgent {
    pub fn new(
        handle: Handle,
        vsock_client: Box<dyn VsockClient + Send + Sync>,
        sev_firmware_factory: SevFirmwareFactory,
        sev_root_certificate_verification: SevRootCertificateVerification,
        trusted_execution_environment_config: TrustedExecutionEnvironmentConfig,
        registry_client: Arc<dyn RegistryClient>,
        store_device_path: PathBuf,
        store_luks_header_path: PathBuf,
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
            store_device_path,
            store_luks_header_path,
            port,
            success_timeout,
        }
    }

    /// Runs the key exchange flow for upgrading to `replica_version`.
    /// Note that the implementation does not verify that `replica_version` is an elected version,
    /// it is the caller's responsibility to select the right target version.
    pub async fn exchange_keys(
        &self,
        replica_version: &ReplicaVersion,
    ) -> Result<(), DiskEncryptionKeyExchangeError> {
        // Channel to communicate the success status of the key exchange.
        let (status_sender, mut status_receiver) = watch::channel(Ok(()));

        let certified_key =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(|err| {
                DiskEncryptionKeyExchangeError::ServerStartError(format!(
                    "Failed to generate self-signed certificate: {err}"
                ))
            })?;

        let expected_measurements = self.fetch_launch_measurements(replica_version)?;

        let upgrade_service = Arc::new(DiskEncryptionKeyExchangeServiceImpl::new(
            self.sev_firmware_factory.clone(),
            self.sev_root_certificate_verification,
            certified_key.key_pair.public_key_der(),
            self.trusted_execution_environment_config.clone(),
            self.store_device_path.clone(),
            self.store_luks_header_path.clone(),
            status_sender,
            expected_measurements,
            self.fetch_elected_guestos_versions(),
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
            .map_err(|err| DiskEncryptionKeyExchangeError::UpgradeVmError(err.to_string()))?
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

    fn fetch_launch_measurements(
        &self,
        replica_version: &ReplicaVersion,
    ) -> Result<Vec<Vec<u8>>, DiskEncryptionKeyExchangeError> {
        let registry_version = self.registry_client.get_latest_version();
        let expected_measurements = self
            .registry_client
            .get_replica_version_record(replica_version, registry_version)
            .map_err(|err| {
                DiskEncryptionKeyExchangeError::ServerStartError(format!(
                    "Failed to get replica version record for {replica_version}: {err}"
                ))
            })?
            .ok_or_else(|| {
                DiskEncryptionKeyExchangeError::ServerStartError(format!(
                    "Replica version record for {replica_version} not found in registry"
                ))
            })?
            .guest_launch_measurements
            .ok_or_else(|| {
                DiskEncryptionKeyExchangeError::ServerStartError(format!(
                    "Replica version {replica_version} does not have guest launch measurements"
                ))
            })?
            .guest_launch_measurements
            .into_iter()
            .map(|measurement| measurement.measurement)
            .collect();
        Ok(expected_measurements)
    }

    /// Returns the GuestOS versions elected in the local registry along with their launch
    /// measurements. They tell the client which version we run, see
    /// `GetDiskEncryptionKeyResponse::guestos_version`. That is only a hint, so a failure to read
    /// them is logged and results in an empty list instead of failing the key exchange.
    fn fetch_elected_guestos_versions(&self) -> Vec<ElectedGuestOsVersion> {
        let registry_version = self.registry_client.get_latest_version();
        let records = match self
            .registry_client
            .get_all_replica_version_records(registry_version)
        {
            Ok(records) => records.unwrap_or_default(),
            Err(err) => {
                eprintln!(
                    "Failed to get elected GuestOS versions at registry version \
                     {registry_version}: {err}"
                );
                vec![]
            }
        };

        records
            .into_iter()
            .map(|record| ElectedGuestOsVersion {
                guestos_version: record.replica_version_id,
                launch_measurements: record
                    .guest_launch_measurements
                    .unwrap_or_default()
                    .guest_launch_measurements
                    .into_iter()
                    .map(|measurement| measurement.measurement)
                    .collect(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, KeyPair};
    use x509_parser::parse_x509_certificate;

    /// An ECDSA P-256 key, the key type that `rcgen::generate_simple_self_signed` generates.
    const KEY_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTW3oNh4fZ2BdQbRD
4LVbwRzBBCnnAvby+G+8cRHJYh+hRANCAASgQi7qTaVwu34yXsj6IOQGjuH6Riip
5nnWney+4BN4ZozF96gIwwKdn7B4xYv15Vcz8o8pSUtWaOLZc7Yv7lsE
-----END PRIVATE KEY-----";

    /// The SubjectPublicKeyInfo of `KEY_PKCS8_PEM`, as encoded by OpenSSL.
    const PUBLIC_KEY_DER_HEX: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004a0422eea4da570bb7e325ec8fa20e4068ee1fa4628a9e679d69decbee01378668cc5f7a808c3029d9fb078c58bf5e55733f28f29494b5668e2d973b62fee5b04";

    /// Each party of the key exchange puts two public keys into the custom data of its
    /// attestation report: its own, from `KeyPair::public_key_der`, and its peer's, from the
    /// peer's certificate. The custom data of the two parties match only if `public_key_der`
    /// returns exactly the SubjectPublicKeyInfo that the certificate contains.
    #[test]
    fn own_public_key_is_the_subject_public_key_info_of_the_certificate() {
        let key_pair = KeyPair::from_pem(KEY_PKCS8_PEM).unwrap();
        let certificate = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let (_, x509) = parse_x509_certificate(certificate.der()).unwrap();

        let public_key_der = key_pair.public_key_der();

        assert_eq!(hex::encode(&public_key_der), PUBLIC_KEY_DER_HEX);
        assert_eq!(public_key_der, x509.public_key().raw);
    }
}
