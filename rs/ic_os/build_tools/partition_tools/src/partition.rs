use std::path::{Path, PathBuf};

use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Partition: Sized {
    /// Open a partition for writing. If `index` is Some, the `index`th partition (1-based) in the
    /// disk image is opened.
    async fn open(image: PathBuf, index: Option<u32>) -> Result<Self>;

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
    /// leading to `to` must already exist. If `to` is a directory, the filename
    /// from `from` will be used.
    async fn copy_file_to(&mut self, from: &Path, to: &Path) -> Result<()>;
}
