use crate::crypt::{activate_crypt_device, format_crypt_device};
use crate::partitions::PartitionSetup;
use crate::{DiskEncryption, Partition};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

pub const DEFAULT_GENERATED_KEY_PATH: &'static str = "/boot/config/store.keyfile";

pub struct GeneratedKeyDiskEncryption<'a> {
    pub partition_setup: &'a PartitionSetup,
    pub key_path: &'a Path,
}

impl DiskEncryption for GeneratedKeyDiskEncryption<'_> {
    fn open(&mut self, partition: Partition, crypt_name: &str) -> Result<()> {
        activate_crypt_device(
            partition.device_path(&self.partition_setup),
            crypt_name,
            &self.generate_or_read_key()?,
        )
        .context("Failed to initialize crypt device")?;

        Ok(())
    }

    fn format(&mut self, partition: Partition) -> Result<()> {
        format_crypt_device(
            partition.device_path(&self.partition_setup),
            &self.generate_or_read_key()?,
        )
        .context("Failed to format crypt device")?;

        Ok(())
    }
}

impl GeneratedKeyDiskEncryption<'_> {
    fn generate_or_read_key(&self) -> Result<Vec<u8>> {
        if !self.key_path.exists() {
            // Generate a new random key and persist it atomically. Avoid race conditions with other
            // processes by using a temporary file.
            let parent_dir = self
                .key_path
                .parent()
                .context("Could not find parent directory for key file")?;
            let mut temp = NamedTempFile::new_in(parent_dir)
                .context("Could not create temporary file for boot partition key")?;
            let rand_key = rand::random::<[u8; 16]>();
            temp.write_all(&rand_key)
                .context("Could not write generated key")?;

            match temp
                .persist_noclobber(self.key_path)
                .context("Could not persist boot partition key")
            {
                Ok(_) => {
                    println!(
                        "Generated disk encryption key and saved it to {}",
                        self.key_path.display()
                    );
                    return Ok(rand_key.to_vec());
                }
                Err(err) => {
                    if !self.key_path.exists() {
                        return Err(err);
                    }
                    // If the file was created in the meantime by a concurrent process, fall through
                    // to reading it.
                }
            }
        }

        // Read the existing key from disk
        let existing_key =
            std::fs::read(self.key_path).context("Could not read existing key file")?;
        Ok(existing_key)
    }
}
