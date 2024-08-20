use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::process::Command;

use crate::partition;
use crate::Partition;

pub struct FatPartition {
    index: Option<usize>,
    original: PathBuf,
}

#[async_trait]
impl Partition for FatPartition {
    /// Open a fat3 partition for writing, via mtools. There is nothing to do
    /// here, as mtools works in place.
    async fn open(image: PathBuf, index: Option<usize>) -> Result<Self> {
        Ok(FatPartition {
            index,
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
        let out = if let Some(index) = self.index {
            let offset = partition::check_offset(&self.original, index).await?;

            Command::new("mcopy")
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
            Command::new("mcopy")
                .args([
                    "-o",
                    "-i",
                    &format!("{}", self.original.display()),
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
        let out = if let Some(index) = self.index {
            let offset = partition::check_offset(&self.original, index).await?;

            Command::new("mcopy")
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
            Command::new("mcopy")
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
}
