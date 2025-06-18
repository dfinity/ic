use std::path::{Path, PathBuf};

use crate::exes::mcopy;
use anyhow::{anyhow, ensure, Context, Result};
use async_trait::async_trait;
use tokio::process::Command;

use crate::partition;
use crate::Partition;

pub struct FatPartition {
    offset_bytes: Option<u64>,
    original: PathBuf,
}

#[async_trait]
impl Partition for FatPartition {
    /// Open a fat3 partition for writing, via mtools. There is nothing to do
    /// here, as mtools works in place.
    async fn open(image: PathBuf, index: Option<usize>) -> Result<Self> {
        let _ = mcopy().context("mcopy is needed to open FAT partitions")?;
        let mut offset = None;
        if let Some(index) = index {
            offset = Some(partition::check_offset(&image, index).await?);
        }
        Ok(FatPartition {
            offset_bytes: offset,
            original: image,
        })
    }

    async fn open_range(image: PathBuf, offset_bytes: u64, _length_bytes: u64) -> Result<Self> {
        Ok(Self {
            offset_bytes: Some(offset_bytes),
            original: image,
        })
    }

    /// Close a fat32 partition. There is nothing to do here, as mtools works
    /// in place.
    async fn close(self) -> Result<()> {
        Ok(())
    }

    /// Copy a file into place
    async fn write_file(&mut self, input: &Path, output: &Path) -> Result<()> {
        let mcopy = mcopy().context("mcopy is needed to write files")?;
        let out = if let Some(offset) = self.offset_bytes {
            Command::new(mcopy)
                .args([
                    "-o",
                    "-i",
                    &format!("{}@@{}", self.original.display(), offset),
                    &input.display().to_string(),
                    &format!("::{}", output.display()),
                ])
                .output()
                .await
                .context("failed to run mcopy")?
        } else {
            Command::new(mcopy)
                .args([
                    "-o",
                    "-i",
                    &self.original.display().to_string(),
                    &input.display().to_string(),
                    &format!("::{}", output.display()),
                ])
                .output()
                .await
                .context("failed to run mcopy")?
        };

        if !out.status.success() {
            return Err(anyhow!("mcopy failed: {}", String::from_utf8(out.stderr)?));
        }

        Ok(())
    }

    /// Read a file from a given partition
    async fn read_file(&mut self, input: &Path) -> Result<String> {
        let mcopy = mcopy().context("mcopy is needed to write files")?;
        let out = if let Some(offset) = self.offset_bytes {
            Command::new(mcopy)
                .args([
                    "-o",
                    "-i",
                    &format!("{}@@{}", self.original.display(), offset),
                    &format!("::{}", input.display()),
                    "-",
                ])
                .output()
                .await
                .context("failed to run mcopy")?
        } else {
            Command::new(mcopy)
                .args([
                    "-o",
                    "-i",
                    &format!("{}", self.original.display()),
                    &format!("::{}", input.display()),
                    "-",
                ])
                .output()
                .await
                .context("failed to run mcopy")?
        };

        if !out.status.success() {
            return Err(anyhow!("mcopy failed: {}", String::from_utf8(out.stderr)?));
        }

        Ok(String::from_utf8(out.stdout)?)
    }

    async fn copy_files_to(&mut self, output: &Path) -> Result<()> {
        let mcopy = mcopy().context("mcopy is needed to extract contents")?;

        ensure!(
            output.exists() && output.is_dir(),
            "output must be an existing directory"
        );

        let out = if let Some(offset) = self.offset_bytes {
            Command::new(mcopy)
                .args([
                    "-s", // recursive copy
                    "-o", // overwrite existing files
                    "-i",
                    &format!("{}@@{}", self.original.display(), offset),
                    "::/", // copy everything from root of FAT partition
                    &output.display().to_string(),
                ])
                .output()
                .await
                .context("failed to run mcopy")?
        } else {
            Command::new(mcopy)
                .args([
                    "-s", // recursive copy
                    "-o", // overwrite existing files
                    "-i",
                    &self.original.display().to_string(),
                    "::/", // copy everything from root of FAT partition
                    &output.display().to_string(),
                ])
                .output()
                .await
                .context("failed to run mcopy")?
        };

        if !out.status.success() {
            return Err(anyhow!("mcopy failed: {}", String::from_utf8(out.stderr)?));
        }

        Ok(())
    }
}
