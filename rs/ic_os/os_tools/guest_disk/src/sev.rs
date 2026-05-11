use crate::crypt::{
    LuksHeaderLocation, activate_crypt_device, backup_luks_header_to_file, check_encryption_key,
    destroy_key_slots_except, format_crypt_device,
};
use crate::{DiskEncryption, Partition, activate_flags};
use anyhow::{Context, Result, bail};
use config_types::GuestVMType;
use sev_guest::firmware::SevGuestFirmware;
use sev_guest::key_deriver::{Key, derive_key_from_sev_measurement};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub struct SevDiskEncryption {
    pub sev_firmware: Box<dyn SevGuestFirmware>,
    pub previous_key_path: PathBuf,
    pub store_luks_header_path: PathBuf,
    pub guest_vm_type: GuestVMType,
    pub metrics_file: PathBuf,
}

impl SevDiskEncryption {
    fn ensure_detached_store_luks_header(&self, device_path: &Path) -> Result<()> {
        let detached_header_exists = self.store_luks_header_path.exists();

        info!(
            "Backing up attached Store LUKS header from {} to {}",
            device_path.display(),
            self.store_luks_header_path.display()
        );
        if let Err(err) = backup_luks_header_to_file(device_path, &self.store_luks_header_path)
            .with_context(|| {
                format!(
                    "Failed to persist detached Store LUKS header to {}",
                    self.store_luks_header_path.display()
                )
            })
        {
            if !detached_header_exists {
                return Err(err);
            }

            warn!(
                "Failed to refresh detached Store LUKS header from attached header on {}: \
                {err:#}. Using existing detached header at {}",
                device_path.display(),
                self.store_luks_header_path.display()
            );
        }

        Ok(())
    }

    fn setup_store_with_previous_key(
        &self,
        device_path: &Path,
        crypt_name: &str,
        new_key: &[u8],
    ) -> Result<()> {
        let previous_key = std::fs::read(&self.previous_key_path).with_context(|| {
            format!(
                "Could not read previous key from {}",
                self.previous_key_path.display()
            )
        })?;
        info!("Found previous key for store partition, will use it to unlock the partition");
        let mut crypt_device = activate_crypt_device(
            device_path,
            LuksHeaderLocation::Detached(&self.store_luks_header_path),
            crypt_name,
            &previous_key,
            activate_flags(Partition::Store),
            /*verify_luks_params=*/ true,
            Some(self.metrics_file.as_path()),
        )
        .context("Failed to unlock store partition with previous key")?;

        info!("Adding new SEV key to store partition");
        crypt_device
            .keyslot_handle()
            .add_by_passphrase(None, &previous_key, new_key)
            .context("Failed to add new key to store partition")?;

        info!("Removing old key slots from store partition");
        // Keep the key slot that was used to unlock the partition with the previous key.
        // Delete all other key slots and add the new key.
        // In the end, the store partition will have two keys:
        // 1. The previous key that was used to unlock the partition before the upgrade.
        // 2. The new key that is used to unlock the partition after the upgrade.
        if let Err(err) = destroy_key_slots_except(&mut crypt_device, &[&previous_key, new_key]) {
            // It's not a critical error if we fail to destroy the key slots, but it's a security
            // risk, so we should log it. We panic in debug builds.
            debug_assert!(false, "Failed to destroy key slots: {err:?}");
            warn!("Failed to destroy key slots: {err:?}");
        }

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
                    Some(&self.metrics_file),
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
                    match self.setup_store_with_previous_key(
                        device_path,
                        crypt_name,
                        key.as_bytes(),
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
                    Some(&self.metrics_file),
                )
                .context("Failed to initialize crypt device for store partition")?;
            }
        }

        Ok(())
    }

    fn format(&mut self, device_path: &Path, partition: Partition) -> Result<()> {
        if partition == Partition::Store && self.store_luks_header_path.exists() {
            bail!(
                "Refusing to format Store because detached LUKS header {} already exists. Remove \
                the stale header first if you really want to reformat the device.",
                self.store_luks_header_path.display()
            );
        }

        let key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
        )
        .context("Failed to derive SEV key for disk encryption")?;

        // For now, we use attached headers and for store partition, we create a detached
        // backup. Once all GuestOS-s support detached headers, we can switch to using only detached
        // headers.
        // TODO: Remove attached header usage for store partition
        format_crypt_device(device_path, LuksHeaderLocation::Attached, key.as_bytes())
            .context("Failed to format partition")?;

        if partition == Partition::Store {
            self.ensure_detached_store_luks_header(device_path)?;
        }

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

    /// Persists a detached LUKS header for the Store partition at `luks_header_path`.
    fn backup_luks_header(&self, device_path: &Path, luks_header_path: &Path) -> Result<()>;
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

    fn backup_luks_header(&self, device_path: &Path, luks_header_path: &Path) -> Result<()> {
        backup_luks_header_to_file(device_path, luks_header_path)
    }
}
