use crate::crypt::{activate_crypt_device, FormatOptions};
use crate::partitions::PartitionSetup;
use crate::Partition;
use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

pub const GENERATED_KEY_PATH: &'static str = "/boot/config/store.keyfile";

pub fn setup_disk_encryption_with_generated_key(
    partition: Partition,
    partition_setup: &PartitionSetup,
    crypt_name: &str,
    key_path: &Path,
    format_options: FormatOptions,
) -> Result<()> {
    let key = generate_or_read_key(key_path)?;
    let device = match partition {
        Partition::Var => &partition_setup.my_var_partition_device,
        Partition::Store => &partition_setup.store_partition_device,
    };

    activate_crypt_device(&device, crypt_name, &key, format_options).with_context(|| {
        format!("Failed to initialize crypt device for partition {partition:?}",)
    })?;

    Ok(())
}

fn generate_or_read_key(key_path: &Path) -> Result<Vec<u8>> {
    if !key_path.exists() {
        // Generate a new random key and persist it atomically. Avoid race conditions with other
        // processes by using a temporary file.
        let parent_dir = key_path
            .parent()
            .context("Could not find parent directory for key file")?;
        let mut temp = NamedTempFile::new_in(parent_dir)
            .context("Could not create temporary file for boot partition key")?;
        let rand_key = rand::random::<[u8; 16]>();
        temp.write_all(&rand_key)
            .context("Could not write generated key")?;

        match temp
            .persist_noclobber(key_path)
            .context("Could not persist boot partition key")
        {
            Ok(_) => {
                println!(
                    "Generated disk encryption key and saved it to {}",
                    key_path.display()
                );
                return Ok(rand_key.to_vec());
            }
            Err(err) => {
                if !key_path.exists() {
                    return Err(err);
                }
                // If the file was created in the meantime by a concurrent process, fall through to
                // reading it.
            }
        }
    }

    // Read the existing key from disk
    let existing_key = std::fs::read(key_path).context("Could not read existing key file")?;
    Ok(existing_key)
}
