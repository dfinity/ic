use crate::crypt::{activate_crypt_device, destroy_key_slots_except, FormatOptions};
use crate::partitions::PartitionSetup;
use crate::Partition;
use anyhow::{bail, Context, Result};
use ic_sev::guest::key_deriver::{Key, SevKeyDeriver};
use std::path::Path;

pub const PREVIOUS_KEY_PATH: &'static str = "/var/alternative_store.keyfile";

pub struct SevDiskEncryption<'a> {
    pub partition: Partition,
    pub partition_setup: &'a PartitionSetup,
    pub sev_key_deriver: &'a mut SevKeyDeriver,
    pub previous_key_path: &'a Path,
}

impl SevDiskEncryption<'_> {
    pub fn open(&self, crypt_name: &str) -> Result<()> {
        match self.partition {
            Partition::Var => {
                let key = self
                    .sev_key_deriver
                    .derive_key(Key::VarPartitionEncryptionKey)
                    .context("Failed to derive SEV key for var partition")?;

                activate_crypt_device(
                    &self.partition_setup.my_var_partition_device,
                    crypt_name,
                    &key,
                )
                .context("Failed to initialize crypt device for var partition")?;
            }

            Partition::Store => {
                let new_key = sev_key_deriver
                    .derive_key(Key::StorePartitionEncryptionKey)
                    .context("Failed to derive SEV key for store partition")?;

                // Try to read the previous SEV key. This is the key that the previous version of the
                // GuestOS used to unlock the data (store) partition. During the upgrade this key is
                // written to `previous_key_path`. After the upgrade, when the GuestOS boots for the
                // first time, it unlocks the disk using the previous key and adds its own key.
                if previous_key_path.exists() {
                    println!(
                        "Unlocking store with existing key from {}",
                        previous_key_path.display()
                    );
                    match init_store_with_previous_key(
                        &partition_setup.store_partition_device,
                        crypt_name,
                        &new_key,
                        &previous_key_path,
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
                    &partition_setup.store_partition_device,
                    crypt_name,
                    &new_key,
                    format_options,
                )
                .context("Failed to initialize crypt device for store partition")?;
            }
        }

        Ok(())
    }

    fn format(&self) {}
}

pub fn setup_disk_encryption_with_sev(
    partition: Partition,
    partition_setup: &PartitionSetup,
    crypt_name: &str,
    sev_key_deriver: &mut SevKeyDeriver,
    previous_key_path: &Path,
    format_options: FormatOptions,
) -> Result<()> {
}

fn init_store_with_previous_key(
    store_device: &Path,
    crypt_name: &str,
    new_key: &[u8],
    previous_key_path: &Path,
) -> Result<()> {
    let previous_key = std::fs::read(&previous_key_path).with_context(|| {
        format!(
            "Could not read previous key from {}",
            previous_key_path.display()
        )
    })?;
    let mut crypt_device = activate_crypt_device(
        store_device,
        crypt_name,
        &previous_key,
        FormatOptions {
            allow_if_uninit: false,
            allow_if_cannot_activate: false,
        },
    )
    .context("Failed to unlock store partition with previous key")?;

    // Keep the key slot that was used to unlock the partition with the previous key.
    // Delete all other key slots and add the new key.
    // In the end, the store partition will have two keys:
    // 1. The previous key that was used to unlock the partition before the upgrade.
    // 2. The new key that is used to unlock the partition after the upgrade.
    if let Err(err) = destroy_key_slots_except(&mut crypt_device, &previous_key) {
        debug_assert!(false, "Failed to destroy key slots: {err:?}");
        eprintln!("Failed to destroy key slots: {err:?}");
    }

    crypt_device
        .keyslot_handle()
        .add_by_passphrase(None, &previous_key, new_key)
        .context("Failed to add new key to store partition")?;

    Ok(())
}
