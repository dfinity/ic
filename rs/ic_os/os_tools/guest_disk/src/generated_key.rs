use crate::crypt::{activate_crypt_device, format_crypt_device};
use crate::{DiskEncryption, Partition, activate_flags};
use anyhow::{Context, Result};
use ic_sys::fs::{Clobber, write_atomically_using_tmp_file};
use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub const DEFAULT_GENERATED_KEY_PATH: &str = "/boot/config/store.keyfile";
const GENERATED_KEY_SIZE_BYTES: usize = 16;

pub struct GeneratedKeyDiskEncryption<'a> {
    pub key_path: &'a Path,
}

impl DiskEncryption for GeneratedKeyDiskEncryption<'_> {
    fn open(&mut self, device_path: &Path, partition: Partition, crypt_name: &str) -> Result<()> {
        let disk_encryption_key = self.generate_or_read_key()?;
        activate_crypt_device(
            device_path,
            crypt_name,
            &disk_encryption_key,
            activate_flags(partition),
        )
        .context("Failed to initialize crypt device")?;

        Ok(())
    }

    fn format(&mut self, device_path: &Path, _partition: Partition) -> Result<()> {
        format_crypt_device(device_path, &self.generate_or_read_key()?)
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
            let temp = tempfile::Builder::new()
                .permissions(Permissions::from_mode(0o600))
                .tempfile_in(parent_dir)
                .context("Could not create temporary file for boot partition key")?;
            let rand_key = rand::random::<[u8; GENERATED_KEY_SIZE_BYTES]>();
            match write_atomically_using_tmp_file(self.key_path, temp.path(), Clobber::No, |buf| {
                buf.write_all(&rand_key)
            }) {
                Ok(_) => {
                    println!(
                        "Generated disk encryption key and saved it to {}",
                        self.key_path.display()
                    );
                    return Ok(rand_key.to_vec());
                }
                Err(err) => {
                    if !self.key_path.exists() {
                        return Err(err.into());
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
