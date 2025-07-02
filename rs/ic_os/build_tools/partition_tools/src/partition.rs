use std::format;
use std::path::{Path, PathBuf};

use crate::exes::fdisk;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::process::Command;

#[async_trait]
pub trait Partition: Sized {
    /// Open a partition for writing. If `index` is Some, the `index`th partition (1-based) in the
    /// disk image is opened.
    async fn open(image: PathBuf, index: Option<usize>) -> Result<Self>;

    /// Open a partition for writing using explicit offset and length
    async fn open_range(image: PathBuf, offset_bytes: u64, length_bytes: u64) -> Result<Self>;

    /// Close a partition, and write back to the input disk
    async fn close(self) -> Result<()>;

    /// Copy a file into place
    async fn write_file(&mut self, input: &Path, output: &Path) -> Result<()>;

    /// Read a file from a given partition
    async fn read_file(&mut self, input: &Path) -> Result<Vec<u8>>;

    /// Copy all files from a partition to the output directory. `output` must point to an existing
    /// directory.
    async fn copy_files_to(&mut self, output: &Path) -> Result<()>;

    /// Copy a single file from a partition to the output destination. The path
    /// to `output` must already exist.
    async fn copy_file_to(&mut self, input: &Path, output: &Path) -> Result<()>;
}

/// Use fdisk to check the byte offset of a given partition
pub async fn check_offset(disk_image: &Path, index: usize) -> Result<u64> {
    /*
    Example output:
    Disk /srv/images/setupos.node-908.img: 3.78 GiB, 4039114752 bytes, 7888896 sectors
    Units: sectors of 1 * 512 = 512 bytes
    Sector size (logical/physical): 512 bytes / 512 bytes
    I/O size (minimum/optimal): 512 bytes / 512 bytes
    Disklabel type: gpt
    Disk identifier: 2B110BB7-CDEC-7D41-B97E-893EDCBE5428

    Device                              Start
    /srv/images/setupos.node-908.img1    2048
    /srv/images/setupos.node-908.img2  206848
    /srv/images/setupos.node-908.img3  411648
    /srv/images/setupos.node-908.img4  514048
    /srv/images/setupos.node-908.img5 4098048
    /srv/images/setupos.node-908.img6 4302848
    */

    let prefix = disk_image.to_str().expect("Path is not valid UTF-8");

    let out = Command::new(fdisk().context("fdisk is needed to check offsets")?)
        .args([
            "-l",
            &disk_image.display().to_string(),
            "-o",
            "device,start",
        ])
        .output()
        .await
        .context("Failed to run fdisk")?;

    if !out.status.success() {
        return Err(anyhow!("fdisk failed: {}", String::from_utf8(out.stderr)?));
    }

    let line = std::str::from_utf8(&out.stdout)?
        .lines()
        .find(|v| v.starts_with(&format!("{}{}", prefix, index)))
        .with_context(|| format!("Partition index '{index}' not found in image"))?;
    let offset = line
        .split_ascii_whitespace()
        .nth(1)
        .context("Unable to parse fdisk output")?;

    // Assume 512 byte sectors
    Ok(offset.parse::<u64>()? * 512)
}

/// Use fdisk to check the byte size of a given partition
pub async fn check_length(disk_image: &Path, index: usize) -> Result<u64> {
    let prefix = disk_image.to_str().expect("Path is not valid UTF-8");

    let out = Command::new(fdisk().context("fdisk is needed to check lengths")?)
        .args([
            "-l",
            &disk_image.display().to_string(),
            "-o",
            "device,sectors",
        ])
        .output()
        .await
        .context("Failed to run fdisk")?;

    if !out.status.success() {
        return Err(anyhow!("fdisk failed: {}", String::from_utf8(out.stderr)?));
    }

    let line = std::str::from_utf8(&out.stdout)?
        .lines()
        .find(|v| v.starts_with(&format!("{}{}", prefix, index)))
        .expect("Partition index '{index}' not found in image");
    let offset = line
        .split_ascii_whitespace()
        .nth(1)
        .expect("Unable to parse fdisk output");

    // Assume 512 byte sectors
    Ok(offset.parse::<u64>()? * 512)
}
