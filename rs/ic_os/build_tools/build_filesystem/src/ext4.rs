use crate::fs_builder::{FileEntry, FilesystemBuilder};
use crate::partition_size::PartitionSize;
use crate::tar::TarBuilder;
use anyhow::{Context, Result, ensure};
use std::path::PathBuf;
use std::process::Command;
use tar::Builder;
use tempfile::NamedTempFile;

/// Implementation of FilesystemBuilder for ext4 filesystems
///
/// This builder creates a tar file using TarBuilder, then converts it to an ext4
/// filesystem image using mke2fs.
pub struct Ext4Builder {
    tar_builder: TarBuilder<NamedTempFile>,
    output_path: PathBuf,
    partition_size: PartitionSize,
    label: Option<String>,
    mke2fs_path: Option<PathBuf>,
}

impl Ext4Builder {
    /// Create a new Ext4Builder
    ///
    /// * `output_path` - Path where the final ext4 image will be written
    /// * `partition_size` - Size of the partition
    /// * `label` - Optional volume label for the filesystem
    /// * `mke2fs_path` - Optional path to mke2fs binary (defaults to system mke2fs)
    pub fn new(
        output_path: impl Into<PathBuf>,
        partition_size: PartitionSize,
        label: Option<String>,
        mke2fs_path: Option<PathBuf>,
    ) -> Result<Self> {
        let tar_file = NamedTempFile::new().context("Failed to create temporary tar file")?;
        let tar_builder = TarBuilder::new(Builder::new(tar_file));

        Ok(Self {
            tar_builder,
            output_path: output_path.into(),
            partition_size,
            label,
            mke2fs_path,
        })
    }
}

impl FilesystemBuilder for Ext4Builder {
    fn append_entry(&mut self, entry: FileEntry<'_>) -> Result<()> {
        self.tar_builder.append_entry(entry)
    }

    fn finish(self: Box<Self>) -> Result<()> {
        let mut tar_builder = self.tar_builder.into_inner();
        tar_builder.finish()?;
        let tar_file = tar_builder.into_inner()?;

        let mke2fs_binary = self
            .mke2fs_path
            .as_deref()
            .unwrap_or_else(|| std::path::Path::new("mke2fs"));

        let output = Command::new(mke2fs_binary)
            .arg("-t")
            .arg("ext4")
            .arg("-E")
            .arg("hash_seed=c61251eb-100b-48fe-b089-57dea7368612")
            .arg("-U")
            .arg("clear")
            .arg("-d")
            .arg(tar_file.path())
            .arg("-F")
            .arg(&self.output_path)
            .arg(self.partition_size.as_kb()?.to_string())
            .arg("-L")
            .arg(self.label.as_deref().unwrap_or(""))
            .env("SOURCE_DATE_EPOCH", "0")
            .output()
            .context("Failed to execute mke2fs")?;

        ensure!(output.status.success(), "mke2fs failed {output:?}");

        Ok(())
    }

    fn needs_lost_found(&self) -> bool {
        true
    }
}
