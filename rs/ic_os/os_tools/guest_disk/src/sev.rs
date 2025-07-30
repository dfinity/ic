use crate::crypt::{activate_crypt_device, destroy_key_slots_except, format_crypt_device};
use crate::partitions::PartitionSetup;
use crate::{DiskEncryption, Partition};
use anyhow::{Context, Result};
use ic_sev::guest::key_deriver::{Key, SevKeyDeriver};
use std::path::Path;

pub const PREVIOUS_KEY_PATH: &'static str = "/var/alternative_store.keyfile";

pub struct SevDiskEncryption<'a> {
    pub partition_setup: &'a PartitionSetup,
    pub sev_key_deriver: &'a mut SevKeyDeriver,
    pub previous_key_path: &'a Path,
}

impl SevDiskEncryption<'_> {
    fn setup_with_previous_key(&self, crypt_name: &str, new_key: &[u8]) -> Result<()> {
        let previous_key = std::fs::read(&self.previous_key_path).with_context(|| {
            format!(
                "Could not read previous key from {}",
                self.previous_key_path.display()
            )
        })?;
        let mut crypt_device = activate_crypt_device(
            &self.partition_setup.store_partition_device,
            crypt_name,
            &previous_key,
        )
        .context("Failed to unlock store partition with previous key")?;

        // Keep the key slot that was used to unlock the partition with the previous key.
        // Delete all other key slots and add the new key.
        // In the end, the store partition will have two keys:
        // 1. The previous key that was used to unlock the partition before the upgrade.
        // 2. The new key that is used to unlock the partition after the upgrade.
        if let Err(err) = destroy_key_slots_except(&mut crypt_device, &previous_key) {
            // It's not a critical error if we fail to destroy the key slots, but it's a security
            // risk, so we should log it.
            debug_assert!(false, "Failed to destroy key slots: {err:?}");
            eprintln!("Failed to destroy key slots: {err:?}");
        }

        crypt_device
            .keyslot_handle()
            .add_by_passphrase(None, &previous_key, new_key)
            .context("Failed to add new key to store partition")?;

        Ok(())
    }
}

impl DiskEncryption for SevDiskEncryption<'_> {
    fn open(&mut self, partition: Partition, crypt_name: &str) -> Result<()> {
        match partition {
            Partition::Var => {
                let key = self
                    .sev_key_deriver
                    .derive_key(Key::VarPartitionEncryptionKey)
                    .context("Failed to derive SEV key for var partition")?;

                activate_crypt_device(
                    &self.partition_setup.my_var_partition_device,
                    crypt_name,
                    key.as_bytes(),
                )
                .context("Failed to open crypt device for var partition")?;
            }

            Partition::Store => {
                let new_key = self
                    .sev_key_deriver
                    .derive_key(Key::StorePartitionEncryptionKey)
                    .context("Failed to derive SEV key for store partition")?;

                // Try to read the previous SEV key. This is the key that the previous version of the
                // GuestOS used to unlock the store (data) partition. During the upgrade this key is
                // written to `previous_key_path`. After the upgrade, when the GuestOS boots for the
                // first time, it unlocks the disk using the previous key and adds its own key.
                if self.previous_key_path.exists() {
                    println!(
                        "Unlocking store with existing key from {}",
                        self.previous_key_path.display()
                    );
                    match self.setup_with_previous_key(crypt_name, new_key.as_bytes()) {
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
                    &self.partition_setup.store_partition_device,
                    crypt_name,
                    new_key.as_bytes(),
                )
                .context("Failed to initialize crypt device for store partition")?;
            }
        }

        Ok(())
    }

    fn format(&mut self, partition: Partition) -> Result<()> {
        match partition {
            Partition::Var => {
                let key = self
                    .sev_key_deriver
                    .derive_key(Key::VarPartitionEncryptionKey)
                    .context("Failed to derive SEV key for var partition")?;
                format_crypt_device(
                    &self.partition_setup.my_var_partition_device,
                    key.as_bytes(),
                )
                .context("Failed to format var partition")?;
            }

            Partition::Store => {
                let key = self
                    .sev_key_deriver
                    .derive_key(Key::StorePartitionEncryptionKey)
                    .context("Failed to derive SEV key for store partition")?;
                format_crypt_device(&self.partition_setup.store_partition_device, key.as_bytes())
                    .context("Failed to format store partition")?;
            }
        }

        Ok(())
    }
}
