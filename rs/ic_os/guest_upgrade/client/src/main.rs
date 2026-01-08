use anyhow::{Context, Result};
use attestation::verification::SevRootCertificateVerification;
use config_tool::{DEFAULT_GUESTOS_CONFIG_OBJECT_PATH, deserialize_config};
use config_types::{GuestOSConfig, GuestVMType};
use guest_disk::DEFAULT_PREVIOUS_SEV_KEY_PATH;
use guest_upgrade_client::create_nns_registry_client;
use guest_upgrade_shared::DEFAULT_SERVER_PORT;
use sev::firmware::guest::Firmware;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

#[tokio::main]
#[cfg(target_os = "linux")]
pub async fn main() -> Result<()> {
    let guestos_config: GuestOSConfig = deserialize_config(DEFAULT_GUESTOS_CONFIG_OBJECT_PATH)
        .context("Failed to deserialize GuestOS config")?;

    if guestos_config.guest_vm_type != GuestVMType::Upgrade {
        println!("Not an upgrade VM, skipping key exchange");
        return Ok(());
    }

    if let Err(err) = try_run_exchange(guestos_config).await {
        eprintln!("Key exchange failed: {err:?}");
        shutdown();
        Err(err)
    } else {
        println!("Key exchange successful. Requesting shutdown.");
        shutdown();
        Ok(())
    }
}

async fn try_run_exchange(guestos_config: GuestOSConfig) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let nns_registry_client = create_nns_registry_client(&guestos_config)?;

    let sev_firmware = Firmware::open().context("Failed to open SEV firmware")?;

    guest_upgrade_client::DiskEncryptionKeyExchangeClientAgent::new(
        guestos_config,
        SevRootCertificateVerification::Verify,
        Box::new(sev_firmware),
        Arc::new(nns_registry_client),
        Box::new(guest_disk::sev::can_open_store),
        PathBuf::from(DEFAULT_PREVIOUS_SEV_KEY_PATH),
        DEFAULT_SERVER_PORT,
    )
    .run()
    .await?;

    Ok(())
}

fn shutdown() {
    let _ = Command::new("shutdown").arg("-h").arg("now").status();
}
