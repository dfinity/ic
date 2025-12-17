use crate::DiskEncryptionKeyExchangeServerAgent;
use anyhow::Context;
use ic_interfaces_registry::RegistryClient;
use std::sync::Arc;
use tokio::runtime::Handle;

#[cfg(target_os = "linux")]
use {
    config::{DEFAULT_GUESTOS_CONFIG_OBJECT_PATH, deserialize_config},
    config_types::GuestOSConfig,
    ic_sev::guest::is_sev_active,
    sev::firmware::guest::Firmware,
    vsock_lib::LinuxVSockClient,
};

/// Creates a new DiskEncryptionKeyExchangeServerAgent to be used by the Orchestrator.
/// Returns None if SEV is not active or if the GuestOS config cannot be read.
#[cfg(target_os = "linux")]
pub fn new_disk_encryption_key_exchange_server_agent_for_orchestrator(
    handle: Handle,
    registry_client: Arc<dyn RegistryClient>,
) -> Option<DiskEncryptionKeyExchangeServerAgent> {
    let is_sev_active = is_sev_active().unwrap_or_else(|err| {
        eprintln!("Failed to check if SEV is active, assuming it is not active: {err:?}");
        false
    });

    if !is_sev_active {
        return None;
    }

    println!("SEV is active, creating DiskEncryptionKeyExchangeServerAgent");

    let guestos_config: GuestOSConfig = match deserialize_config(DEFAULT_GUESTOS_CONFIG_OBJECT_PATH)
    {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to read GuestOS config: {}", e);
            return None;
        }
    };

    if !guestos_config
        .icos_settings
        .enable_trusted_execution_environment
    {
        // Let's double-check that TEE is also enabled in the config
        eprintln!(
            "enable_trusted_execution_environment in ICOSSettings is false but SEV is \
             active, this should never happen!"
        );
        return None;
    }

    let trusted_execution_config = match guestos_config.trusted_execution_environment_config {
        Some(config) => config,
        None => {
            eprintln!("TrustedExecutionEnvironmentConfig missing in GuestOS config");
            return None;
        }
    };

    let sev_firmware_factory =
        Arc::new(|| Ok(Box::new(Firmware::open().context("Could not open SEV firmware")?) as _));

    Some(DiskEncryptionKeyExchangeServerAgent::new(
        handle,
        Box::new(LinuxVSockClient::default()),
        sev_firmware_factory,
        trusted_execution_config,
        registry_client,
    ))
}

/// Non-Linux stub that always returns None.
#[cfg(not(target_os = "linux"))]
pub fn new_disk_encryption_key_exchange_server_agent_for_orchestrator(
    _handle: Handle,
    _registry_client: Arc<dyn RegistryClient>,
) -> Option<DiskEncryptionKeyExchangeServerAgent> {
    None
}
