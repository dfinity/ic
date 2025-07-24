use crate::crypt::{activate, format, is_luks2};
use crate::partitions::PartitionSetup;
use crate::Partition;
use anyhow::{bail, Context, Result};
use ic_sev::guest::key_deriver::{Key, SevKeyDeriver};
use std::path::Path;

pub const PREVIOUS_KEY_PATH: &'static str = "/var/alternative_store.keyfile";

pub fn setup_disk_encryption_with_sev(
    partition: Partition,
    partition_setup: &PartitionSetup,
    sev_key_deriver: &mut SevKeyDeriver,
    previous_key_path: &Path,
) -> Result<()> {
    match partition {
        Partition::Var => {
            if !partition_setup.my_var_partition_device.exists() {
                bail!(
                    "Var partition device does not exist: {}",
                    partition_setup.my_var_partition_device.display()
                );
            }

            let key = sev_key_deriver
                .derive_key(Key::VarPartitionEncryptionKey)
                .context("Failed to derive SEV key for var partition")?;

            if !is_luks2(&partition_setup.my_var_partition_device)
                .context("Failed to check if var partition is luks2")?
            {
                println!("Var partition is not LUKS2, will format it");
                format(&partition_setup.my_var_partition_device, &key)
                    .context("Failed to format var partition")?;
            }

            println!("Opening var partition with SEV key derivation");
            activate(&partition_setup.my_var_partition_device, &key)
                .context("Failed to activate var partition")?;
        }
        Partition::Store => {
            let mut opened = false;
            if let Some(key_from_var) = read_previous_key(previous_key_path) {
                println!("Unlocking store with existing key from /var/store.keyfile");
                opened = activate(&partition_setup.store_partition_device, &key_from_var)
                    .inspect_err(|err| eprintln!("Failed to unlock store: {}", err))
                    .is_ok();
            }
        }
    }

    Ok(())
}

/// Reads the previous SEV key. This is the key that the previous version of the GuestOS used
/// to unlock the data (store) partition. During the upgrade this key is written to
/// `previous_key_path`. After the upgrade, when the GuestOS boots for the first time, it unlocks
/// the disk using the previous key and adds its own key.
fn read_previous_key(previous_key_path: &Path) -> Option<Vec<u8>> {
    if previous_key_path.exists() {
        // If the previous key file exists, read it
        match std::fs::read(&previous_key_path) {
            Ok(key) => Some(key),
            Err(err) => {
                eprintln!(
                    "Could not read previous key from {}: {}",
                    previous_key_path.display(),
                    err
                );
                None
            }
        }
    } else {
        None
    }
}
