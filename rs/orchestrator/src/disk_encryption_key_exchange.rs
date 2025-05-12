// use attestation::attestation_report::SevAttestationPackageGenerator;
// use ic_interfaces::crypto::BasicSigner;
// use ic_interfaces_registry::RegistryClient;
// use ic_os_upgrade::server::DiskEncryptionKeyExchangeServer;
// use ic_os_upgrade::server::DiskEncryptionKeyExchangeServiceImpl;
// use ic_os_upgrade::DiskEncryptionKeyProvider;
// use ic_types::crypto::NodeIdProof;
// use ic_types::NodeId;
// use std::sync::Arc;
// use std::time::Duration;
// use thiserror::Error;
// use tokio::runtime::Handle;
// use tokio::sync::{watch, Notify};
// use vsock_lib::protocol::Command;
// use vsock_lib::VSockClient;
//
// #[derive(Error, Debug)]
// pub enum DiskEncryptionKeyExchangeError {
//     #[error("Server start error: {0}")]
//     ServerStartError(String),
//     #[error("UpgradeVM error: {0}")]
//     UpgradeVmError(String),
// }
//
// pub struct DiskEncryptionKeyExchangeAgent {
//     runtime_handle: Handle,
//     vsock_client: Box<dyn VSockClient + Send + Sync>,
//     attestation_package_generator: Arc<SevAttestationPackageGenerator>,
//     disk_encryption_key_provider: Arc<DiskEncryptionKeyProvider>,
//     node_id: NodeId,
//     signer: Arc<dyn BasicSigner<NodeIdProof> + Send + Sync>,
//     registry_client: Arc<dyn RegistryClient>,
// }
//
// impl DiskEncryptionKeyExchangeAgent {
//     pub fn new(
//         handle: Handle,
//         vsock_client: Box<dyn VSockClient + Send + Sync>,
//         attestation_package_generator: Arc<SevAttestationPackageGenerator>,
//         disk_encryption_key_provider: Arc<DiskEncryptionKeyProvider>,
//         node_id: NodeId,
//         signer: Arc<dyn BasicSigner<NodeIdProof> + Send + Sync>,
//         registry_client: Arc<dyn RegistryClient>,
//     ) -> Self {
//         Self {
//             runtime_handle: handle,
//             vsock_client,
//             attestation_package_generator,
//             disk_encryption_key_provider,
//             node_id,
//             signer,
//             registry_client,
//         }
//     }
//
//     pub async fn exchange_keys(&self) -> Result<(), DiskEncryptionKeyExchangeError> {
//         const SUCCESS_TIMEOUT: Duration = Duration::from_secs(300);
//
//         let (success_sender, mut success_receiver) = watch::channel(false);
//
//         let upgrade_service = Arc::new(DiskEncryptionKeyExchangeServiceImpl::new(
//             self.attestation_package_generator.clone(),
//             self.disk_encryption_key_provider.clone(),
//             success_sender,
//             self.node_id,
//             self.signer.clone(),
//             self.registry_client.clone(),
//         ));
//
//         // Start the server that the Upgrade VM can connect to for getting the keys.
//         // Assign it to _ to keep the server alive until the function returns.
//         let _ = DiskEncryptionKeyExchangeServer::start_new(
//             self.runtime_handle.clone(),
//             upgrade_service,
//         )
//         .await
//         .map_err(|err| DiskEncryptionKeyExchangeError::ServerStartError(err.to_string()))?;
//
//         // Tell the host to start the Upgrade VM.
//         self.vsock_client
//             .send_command(Command::StartUpgradeVm)
//             .map_err(|err| DiskEncryptionKeyExchangeError::UpgradeVmError(err.to_string()))?;
//
//         // Wait for status.
//         match tokio::time::timeout(SUCCESS_TIMEOUT, success_receiver.changed()).await {
//             Ok(Ok(_)) => {
//                 if success_receiver.borrow_and_update() {
//                     Ok(())
//                 } else {
//                     Err(DiskEncryptionKeyExchangeError::UpgradeVmError(
//                         "Upgrade VM failed to complete key exchange".to_string(),
//                     ))
//                 }
//             },
//             Ok(Err(e)) => Err(DiskEncryptionKeyExchangeError::UpgradeVmError(format!(
//                 "Failed to receive key exchange completion: {}", e
//             ))),
//             Err(_) => Err(DiskEncryptionKeyExchangeError::UpgradeVmError(format!(
//                 "Timeout waiting for disk encryption key exchange to complete after {SUCCESS_TIMEOUT:?}"
//             ))),
//         }
//     }
// }
