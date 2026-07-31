use crate::crypt::{
    LuksHeaderLocation, SevMetadata, activate_crypt_device, add_sev_metadata, check_encryption_key,
    destroy_keyslots_except, format_crypt_device,
};
use crate::{DiskEncryption, Partition, activate_flags};
use anyhow::{Context, Result, bail};
use attestation::attestation_report::AttestationReportExt;
use config_types::GuestVMType;
use prometheus::Registry;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use sev_guest::firmware::SevGuestFirmware;
use sev_guest::key_deriver::{Key, derive_key_from_sev_measurement};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub struct SevDiskEncryption {
    pub sev_firmware: Box<dyn SevGuestFirmware>,
    pub previous_key_path: PathBuf,
    pub store_luks_header_path: PathBuf,
    pub guest_vm_type: GuestVMType,
    pub metrics_registry: Registry,
}

impl SevDiskEncryption {
    fn setup_store_with_previous_key(
        &self,
        device_path: &Path,
        crypt_name: &str,
        new_key: &[u8],
        sev_metadata: &SevMetadata,
    ) -> Result<()> {
        let previous_key = std::fs::read(&self.previous_key_path).with_context(|| {
            format!(
                "Could not read previous key from {}",
                self.previous_key_path.display()
            )
        })?;

        info!("Found previous key for store partition, will use it to unlock the partition");
        let (mut crypt_device, previous_keyslot) = activate_crypt_device(
            device_path,
            LuksHeaderLocation::Detached(&self.store_luks_header_path),
            crypt_name,
            &previous_key,
            activate_flags(Partition::Store),
            /*verify_luks_params=*/ true,
            Some(&self.metrics_registry),
        )
        .context("Failed to unlock store partition with previous key")?;

        info!("Adding new SEV key to store partition");
        let new_keyslot = crypt_device
            .keyslot_handle()
            .add_by_passphrase(None, &previous_key, new_key)
            .context("Failed to add new key to store partition")?;

        info!("Removing old key slots from store partition");
        // Keep the key slot that was used to unlock the partition with the previous key.
        // Delete all other key slots and add the new key.
        // In the end, the store partition will have two keys:
        // 1. The previous key that was used to unlock the partition before the upgrade.
        // 2. The new key that is used to unlock the partition after the upgrade.
        destroy_keyslots_except(&mut crypt_device, &[previous_keyslot, new_keyslot])
            .context("Failed to destroy keyslots")?;

        add_sev_metadata(&mut crypt_device, new_keyslot, sev_metadata.clone())
            .context("Failed to write SEV keyslot metadata")?;

        // Clean up the previous key on the first boot after upgrade if own key was added
        // successfully.
        if self.guest_vm_type == GuestVMType::Default {
            info!(
                "Removing previous store key file: {}",
                self.previous_key_path.display()
            );
            if let Err(err) = std::fs::remove_file(&self.previous_key_path) {
                debug_assert!(false, "Failed to remove previous key file: {err:?}");
                warn!("Failed to remove previous key file: {err:?}");
            }
        }

        Ok(())
    }

    fn get_sev_metadata_for_luks(&mut self) -> Result<SevMetadata> {
        let report_bytes = self
            .sev_firmware
            .get_report(None, None, None)
            .context("Failed to get attestation report from SEV firmware")?;
        let report = AttestationReport::from_bytes(&report_bytes)
            .context("Failed to parse attestation report")?;

        Ok(SevMetadata {
            launch_measurement_hex: hex::encode(report.measurement),
            tcb_version: report
                .launch_tcb_as_u64()
                .context("Failed to get launch TCB from attestation report")?,
        })
    }
}

impl DiskEncryption for SevDiskEncryption {
    fn open(&mut self, device_path: &Path, partition: Partition, crypt_name: &str) -> Result<()> {
        let key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
        )
        .context("Failed to derive SEV key for disk encryption")?;

        match partition {
            Partition::Var => {
                activate_crypt_device(
                    device_path,
                    LuksHeaderLocation::Attached,
                    crypt_name,
                    key.as_bytes(),
                    activate_flags(partition),
                    /*verify_luks_params=*/ true,
                    Some(&self.metrics_registry),
                )
                .context("Failed to open crypt device for var partition")?;
            }

            Partition::Store => {
                // Try to read the previous SEV key. This is the key that the previous version of the
                // GuestOS used to unlock the store (data) partition. During the upgrade this key is
                // written to `previous_key_path`. After the upgrade, when the GuestOS boots for the
                // first time, it unlocks the disk using the previous key and adds its own key.

                // Keep this logic consistent with can_open_store below.
                if self.previous_key_path.exists() {
                    info!(
                        "Unlocking store with existing key from {}",
                        self.previous_key_path.display()
                    );
                    let sev_metadata = self.get_sev_metadata_for_luks()?;
                    match self.setup_store_with_previous_key(
                        device_path,
                        crypt_name,
                        key.as_bytes(),
                        &sev_metadata,
                    ) {
                        Ok(()) => return Ok(()),
                        Err(err) => {
                            warn!("Failed to unlock store partition with previous key: {err:?}");
                            // Fall through and try to open the device with the new key
                        }
                    }
                }

                activate_crypt_device(
                    device_path,
                    LuksHeaderLocation::Detached(&self.store_luks_header_path),
                    crypt_name,
                    key.as_bytes(),
                    activate_flags(partition),
                    /*verify_luks_params=*/ true,
                    Some(&self.metrics_registry),
                )
                .context("Failed to initialize crypt device for store partition")?;
            }
        }

        Ok(())
    }

    fn format(&mut self, device_path: &Path, partition: Partition) -> Result<()> {
        let key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
        )
        .context("Failed to derive SEV key for disk encryption")?;

        let sev_metadata = self.get_sev_metadata_for_luks()?;

        let header_location = match partition {
            Partition::Store => {
                if self.store_luks_header_path.exists() {
                    bail!(
                        "Refusing to format Store because detached LUKS header {} already exists. \
                        Remove the stale header first if you really want to reformat the device.",
                        self.store_luks_header_path.display()
                    );
                }
                LuksHeaderLocation::Detached(&self.store_luks_header_path)
            }
            Partition::Var => LuksHeaderLocation::Attached,
        };

        let (mut crypt_device, keyslot) =
            format_crypt_device(device_path, header_location, key.as_bytes())
                .context("Failed to format partition")?;
        add_sev_metadata(&mut crypt_device, keyslot, sev_metadata)
            .context("Failed to write SEV keyslot metadata")?;

        Ok(())
    }
}

/// Check whether we can open the store partition with either the previous key or the SEV derived
/// key.
pub fn can_open_store(
    device_path: &Path,
    previous_key_path: &Path,
    store_luks_header_path: &Path,
    sev_firmware: &mut dyn SevGuestFirmware,
) -> Result<bool> {
    // Keep key selection consistent with open() above.
    if previous_key_path.exists()
        && let Ok(key) = std::fs::read(previous_key_path)
        && check_encryption_key(
            device_path,
            LuksHeaderLocation::Detached(store_luks_header_path),
            &key,
        )
        .is_ok()
    {
        return Ok(true);
    }

    let derived_key =
        derive_key_from_sev_measurement(sev_firmware, Key::DiskEncryptionKey { device_path })?;

    Ok(check_encryption_key(
        device_path,
        LuksHeaderLocation::Detached(store_luks_header_path),
        derived_key.as_bytes(),
    )
    .is_ok())
}

#[mockall::automock]
pub trait DiskCryptoOps: Send + Sync {
    /// Returns whether the Store partition can already be unlocked locally.
    ///
    /// Implementations may use the previous key, the detached LUKS header, and/or the current
    /// SEV-derived key to determine whether key exchange can be skipped.
    fn can_open_store(
        &self,
        device_path: &Path,
        previous_key_path: &Path,
        store_luks_header_path: &Path,
        sev_firmware: &mut dyn SevGuestFirmware,
    ) -> Result<bool>;
}

pub struct DefaultSevStoreCryptoOps;

impl DiskCryptoOps for DefaultSevStoreCryptoOps {
    fn can_open_store(
        &self,
        device_path: &Path,
        previous_key_path: &Path,
        store_luks_header_path: &Path,
        sev_firmware: &mut dyn SevGuestFirmware,
    ) -> Result<bool> {
        can_open_store(
            device_path,
            previous_key_path,
            store_luks_header_path,
            sev_firmware,
        )
    }
}
