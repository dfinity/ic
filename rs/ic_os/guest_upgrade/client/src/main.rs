use anyhow::{Context, Result};
use attestation::verification::SevRootCertificateVerification;
use config::{deserialize_config, DEFAULT_GUESTOS_CONFIG_OBJECT_PATH};
use config_types::GuestOSConfig;
use guest_disk::DEFAULT_PREVIOUS_SEV_KEY_PATH;
use guest_upgrade_client::create_nns_registry_client;
use guest_upgrade_shared::DEFAULT_SERVER_PORT;
use sev::firmware::guest::Firmware;
use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main]
#[cfg(target_os = "linux")]
pub async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let guestos_config: GuestOSConfig = deserialize_config(DEFAULT_GUESTOS_CONFIG_OBJECT_PATH)
        .context("Failed to deserialize GuestOS config")?;
    let nns_registry_client = create_nns_registry_client(&guestos_config)?;

    let sev_firmware = Firmware::open().context("Failed to open SEV firmware")?;

    guest_upgrade_client::DiskEncryptionKeyExchangeClientAgent::new(
        guestos_config.clone(),
        SevRootCertificateVerification::Verify,
        Box::new(sev_firmware),
        Arc::new(nns_registry_client),
        PathBuf::from(DEFAULT_PREVIOUS_SEV_KEY_PATH),
        DEFAULT_SERVER_PORT,
    )
    .run()
    .await?;

    Ok(())
}
