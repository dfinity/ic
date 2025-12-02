use crate::crypt::{
    activate_crypt_device, check_encryption_key, destroy_key_slots_except, format_crypt_device,
};
use crate::{DiskEncryption, Partition, activate_flags};
use anyhow::{Context, Result};
use config_types::GuestVMType;
use ic_sev::guest::firmware::SevGuestFirmware;
use ic_sev::guest::key_deriver::{Key, derive_key_from_sev_measurement};
use std::fs;
use std::path::Path;

pub struct SevDiskEncryption<'a> {
    pub sev_firmware: Box<dyn SevGuestFirmware>,
    pub previous_key_path: &'a Path,
    pub guest_vm_type: GuestVMType,
}

impl SevDiskEncryption<'_> {
    fn setup_store_with_previous_key(
        &self,
        device_path: &Path,
        crypt_name: &str,
        new_key: &[u8],
    ) -> Result<()> {
        let previous_key = std::fs::read(self.previous_key_path).with_context(|| {
            format!(
                "Could not read previous key from {}",
                self.previous_key_path.display()
            )
        })?;
        println!("Found previous key for store partition, will use it to unlock the partition");
        let mut crypt_device = activate_crypt_device(
            device_path,
            crypt_name,
            &previous_key,
            activate_flags(Partition::Store),
        )
        .context("Failed to unlock store partition with previous key")?;

        println!("Adding new SEV key to store partition");
        crypt_device
            .keyslot_handle()
            .add_by_passphrase(None, &previous_key, new_key)
            .context("Failed to add new key to store partition")?;

        println!("Removing old key slots from store partition");
        // Keep the key slot that was used to unlock the partition with the previous key.
        // Delete all other key slots and add the new key.
        // In the end, the store partition will have two keys:
        // 1. The previous key that was used to unlock the partition before the upgrade.
        // 2. The new key that is used to unlock the partition after the upgrade.
        if let Err(err) = destroy_key_slots_except(&mut crypt_device, &[&previous_key, new_key]) {
            // It's not a critical error if we fail to destroy the key slots, but it's a security
            // risk, so we should log it. We panic in debug builds.
            debug_assert!(false, "Failed to destroy key slots: {err:?}");
            eprintln!("Failed to destroy key slots: {err:?}");
        }

        // Clean up the previous key on the first boot after upgrade if own key was added
        // successfully.
        if self.guest_vm_type == GuestVMType::Default {
            println!(
                "Removing previous store key file: {}",
                self.previous_key_path.display()
            );
            if let Err(err) = std::fs::remove_file(self.previous_key_path) {
                debug_assert!(false, "Failed to remove previous key file: {err:?}");
                eprintln!("Failed to remove previous key file: {err:?}");
            }
        }

        Ok(())
    }
}

impl DiskEncryption for SevDiskEncryption<'_> {
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
                    crypt_name,
                    key.as_bytes(),
                    activate_flags(partition),
                )
                .context("Failed to open crypt device for var partition")?;
            }

            Partition::Store => {
                // Try to read the previous SEV key. This is the key that the previous version of the
                // GuestOS used to unlock the store (data) partition. During the upgrade this key is
                // written to `previous_key_path`. After the upgrade, when the GuestOS boots for the
                // first time, it unlocks the disk using the previous key and adds its own key.

                // The logic should be kept consistent with can_open_store below
                if self.previous_key_path.exists() {
                    println!(
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
                            eprintln!(
                                "Failed to unlock store partition with previous key: {err:?}"
                            );
                            // Fall through and try to open the device with the new key
                        }
                    }
                }

                activate_crypt_device(
                    device_path,
                    crypt_name,
                    key.as_bytes(),
                    activate_flags(partition),
                )
                .context("Failed to initialize crypt device for store partition")?;
            }
        }

        Ok(())
    }

    fn format(&mut self, device_path: &Path, _partition: Partition) -> Result<()> {
        let key = derive_key_from_sev_measurement(
            self.sev_firmware.as_mut(),
            Key::DiskEncryptionKey { device_path },
        )
        .context("Failed to derive SEV key for disk encryption")?;

        format_crypt_device(device_path, key.as_bytes()).context("Failed to format partition")?;

        Ok(())
    }
}

/// Check whether we can open the store partition with either the previous key or the SEV derived
/// key.
pub fn can_open_store(
    device_path: &Path,
    previous_key_path: &Path,
    sev_firmware: &mut dyn SevGuestFirmware,
) -> Result<bool> {
    // The logic should be kept consistent with open above
    if previous_key_path.exists()
        && let Ok(key) = fs::read(previous_key_path)
        && check_encryption_key(device_path, &key).is_ok()
    {
        return Ok(true);
    }

    let derived_key =
        derive_key_from_sev_measurement(sev_firmware, Key::DiskEncryptionKey { device_path })?;
    Ok(check_encryption_key(device_path, derived_key.as_bytes()).is_ok())
}
