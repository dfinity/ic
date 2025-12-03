use crate::fs_builder::{FileEntry, FilesystemBuilder};
use crate::partition_size::PartitionSize;
use anyhow::{bail, ensure, Context, Result};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use tempfile::NamedTempFile;

/// FAT filesystem type
#[derive(Debug, Clone, Copy)]
pub enum FatType {
    /// VFAT filesystem
    Vfat,
    /// FAT32 filesystem
    Fat32,
}

/// Implementation of FilesystemBuilder for FAT filesystems (VFAT and FAT32)
///
/// This builder creates a FAT filesystem image using mkfs.vfat and copies
/// files directly using mcopy for each entry.
pub struct FatBuilder {
    output_path: PathBuf,
    partition_size: PartitionSize,
    fat_type: FatType,
    label: Option<String>,
    initialized: bool,
}

impl FatBuilder {
    /// Create a new FatBuilder
    ///
    /// * `output_path` - Path where the final FAT image will be written
    /// * `partition_size` - Size of the partition
    /// * `fat_type` - Type of FAT filesystem (VFAT or FAT32)
    /// * `label` - Optional volume label for the filesystem
    pub fn new(
        output_path: impl Into<PathBuf>,
        partition_size: PartitionSize,
        fat_type: FatType,
        label: Option<String>,
    ) -> Result<Self> {
        Ok(Self {
            output_path: output_path.into(),
            partition_size,
            fat_type,
            label,
            initialized: false,
        })
    }

    /// Initialize the FAT filesystem if not already done
    fn ensure_initialized(&mut self) -> Result<()> {
        if !self.initialized {
            let mut cmd = Command::new("/usr/sbin/mkfs.vfat");

            // Add FAT type flag if FAT32
            if matches!(self.fat_type, FatType::Fat32) {
                cmd.arg("-F").arg("32");
            }

            cmd.arg("-C");

            // Add volume label if provided
            if let Some(ref label) = self.label {
                cmd.arg("-n").arg(label);
            }

            cmd.arg(&self.output_path)
                .arg(self.partition_size.as_kb()?.to_string())
                .env("SOURCE_DATE_EPOCH", "0");

            let output = cmd.output().context("Failed to execute mkfs.vfat")?;

            ensure!(output.status.success(), "mkfs.vfat failed {output:?}");
            self.initialized = true;
        }
        Ok(())
    }
}

impl FilesystemBuilder for FatBuilder {
    fn append_entry(&mut self, entry: FileEntry<'_>) -> Result<()> {
        self.ensure_initialized()?;

        let entry_type = entry.header.entry_type();
        let entry_path = entry.path;
        let fat_path = format!("::{}", entry_path.as_relative_path().display());

        // Skip root directory
        if entry_path.is_root() {
            return Ok(());
        }

        match entry_type {
            tar::EntryType::Directory => {
                // Create directory using mmd
                let output = Command::new("/usr/bin/mmd")
                    .arg("-i")
                    .arg(&self.output_path)
                    .arg(&fat_path)
                    .env("SOURCE_DATE_EPOCH", "0")
                    .output()
                    .with_context(|| {
                        format!(
                            "Failed to execute mmd for {:?}",
                            entry_path.as_relative_path()
                        )
                    })?;

                // mmd returns error if directory already exists, which is fine
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if !stderr.contains("File exists") && !stderr.contains("already exists") {
                        bail!(
                            "mmd failed for {:?}: {output:?}",
                            entry_path.as_relative_path()
                        );
                    }
                }
            }
            tar::EntryType::Regular => {
                // Create a temporary file with the contents
                let mut temp_file =
                    NamedTempFile::new().context("Failed to create temporary file")?;
                std::io::copy(entry.contents, &mut temp_file).with_context(|| {
                    format!(
                        "Failed to write temporary file for {:?}",
                        entry_path.as_relative_path()
                    )
                })?;
                temp_file.flush()?;

                // Copy file using mcopy
                let output = Command::new("mcopy")
                    .arg("-i")
                    .arg(&self.output_path)
                    .arg(temp_file.path())
                    .arg(&fat_path)
                    .env("SOURCE_DATE_EPOCH", "0")
                    .output()
                    .with_context(|| {
                        format!(
                            "Failed to execute mcopy for {:?}",
                            entry_path.as_relative_path()
                        )
                    })?;

                ensure!(
                    output.status.success(),
                    "mcopy failed for {:?}: {output:?}",
                    entry_path.as_relative_path()
                );
            }
            _ => {
                bail!("Unsupported entry type: {:?}", entry_type);
            }
        }

        Ok(())
    }

    fn finish(self: Box<Self>) -> Result<()> {
        // Nothing to do - all files were already copied via mcopy
        Ok(())
    }

    fn needs_lost_found(&self) -> bool {
        false
    }
}

