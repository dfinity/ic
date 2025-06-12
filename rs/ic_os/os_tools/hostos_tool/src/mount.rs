use anyhow::{Context, Error, Result};
use async_trait::async_trait;
use gptman::GPT;
use std::fs::File;
use std::path::{Path, PathBuf};
use sys_mount::{Mount, MountFlags, UnmountDrop, UnmountFlags};
use tempfile::TempDir;

// There are two traits here:
// 1. PartitionProvider (high level): provides access to partitions by name
//    Real implementation: GptPartitionProvider
//    Mock implementation: MockPartitionProvider
// 2. Mounter (low level): mounts raw device ranges (offset + length) to filesystem paths
//    Real implementation: LoopDeviceMounter
//    Mock implementation: ExtractingFilesystemMounter
//
// This separation allows for mocking at different levels.
// For example, an integration test may want to use the prod GptPartitionProvider with a mock
// Mounter (to minimize the use of mocks) while a unit-test may want to use MockPartitionProvider
// (to allow for more fine-grained control).

/// Trait for accessing partitions by name from a device
#[async_trait]
pub trait PartitionProvider: Send + Sync {
    async fn mount_partition(&self, partition_name: &str) -> Result<Box<dyn MountedPartition>>;
}

/// Handles mounting raw device ranges (offset + length) to filesystem paths
#[async_trait]
pub trait Mounter: Send + Sync {
    async fn mount_range(
        &self,
        device: PathBuf,
        offset_bytes: u64,
        len_bytes: u64,
    ) -> Result<Box<dyn MountedPartition>>;
}

/// Represents a mounted partition with access to its filesystem.
/// `MountedPartition` uses RAII to represent the mount. Dropping the object cleans up the mount.
pub trait MountedPartition: Send + Sync {
    fn mount_point(&self) -> &Path;
}

/// GPT-aware partition provider that can mount partitions by name
pub struct GptPartitionProvider {
    device: PathBuf,
    gpt: GPT,
    mounter: Box<dyn Mounter>,
}

impl GptPartitionProvider {
    pub fn new(device: PathBuf) -> Result<Self> {
        Self::with_mounter(device, Box::new(LoopDeviceMounter))
    }

    pub fn with_mounter(device: PathBuf, mounter: Box<dyn Mounter>) -> Result<Self> {
        let gpt = GPT::find_from(&mut File::open(&device).context("Could not open device")?)
            .context("Could not read GPT from device")?;
        Ok(Self {
            device,
            gpt,
            mounter,
        })
    }
}

#[async_trait]
impl PartitionProvider for GptPartitionProvider {
    async fn mount_partition(&self, partition_name: &str) -> Result<Box<dyn MountedPartition>> {
        let partition = self
            .gpt
            .iter()
            .map(|(_, partition)| partition)
            .find(|partition| partition.partition_name.as_str() == partition_name)
            .with_context(|| format!("Could not find partition {partition_name}"))?;

        let offset_bytes = partition.starting_lba * self.gpt.sector_size;
        let len_bytes = partition.size()? * self.gpt.sector_size;

        self.mounter
            .mount_range(self.device.clone(), offset_bytes, len_bytes)
            .await
    }
}

/// Real filesystem mount using system mount with loop device
struct LoopDeviceMount {
    // Field order matters: mount must be dropped before tempdir
    // According to the Rust spec, fields are dropped in the order of declaration.
    mount: UnmountDrop<Mount>,
    _tempdir: TempDir,
}

impl MountedPartition for LoopDeviceMount {
    fn mount_point(&self) -> &Path {
        self.mount.target_path()
    }
}

/// Production filesystem mounter using real system mounts
pub struct LoopDeviceMounter;

#[async_trait]
impl Mounter for LoopDeviceMounter {
    async fn mount_range(
        &self,
        device: PathBuf,
        offset_bytes: u64,
        _len_bytes: u64,
    ) -> Result<Box<dyn MountedPartition>> {
        let mount = tokio::task::spawn_blocking(move || {
            let tempdir = TempDir::new()?;
            let target = tempdir.path();
            Ok::<LoopDeviceMount, Error>(LoopDeviceMount {
                mount: Mount::builder()
                    .loopback_offset(offset_bytes)
                    .flags(MountFlags::RDONLY)
                    .explicit_loopback()
                    .mount_autodrop(device, target, UnmountFlags::empty())?,
                _tempdir: tempdir,
            })
        })
        .await??;
        Ok(Box::new(mount))
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use anyhow::{bail, Context};
    use partition_tools::ext::ExtPartition;
    use partition_tools::fat::FatPartition;
    use partition_tools::Partition;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tempfile::TempDir;

    /// Test partition provider that uses pre-populated directories
    pub struct MockPartitionProvider {
        pub partitions: HashMap<String, Arc<TempDir>>,
    }

    impl MockPartitionProvider {
        pub fn new(partitions: HashMap<String, Arc<TempDir>>) -> Self {
            Self { partitions }
        }
    }

    #[async_trait]
    impl PartitionProvider for MockPartitionProvider {
        async fn mount_partition(&self, partition_name: &str) -> Result<Box<dyn MountedPartition>> {
            let partition = self
                .partitions
                .get(partition_name)
                .with_context(|| format!("Could not find partition {partition_name}"))?;
            Ok(Box::new(MockMount {
                mount_point: partition.clone(),
            }))
        }
    }

    /// Mock mounted partition backed by a temporary directory
    struct MockMount {
        mount_point: Arc<TempDir>,
    }

    impl MountedPartition for MockMount {
        fn mount_point(&self) -> &Path {
            self.mount_point.path()
        }
    }

    /// Filesystem mounter for testing that extracts partition contents to temp directories.
    /// This is an alternative to real filesystem mounts when mounts are not possible (e.g. limited
    /// permissions in tests).
    pub struct ExtractingFilesystemMounter {
        file_overrides: Vec<(PathBuf, Vec<u8>)>,
        file_deletions: Vec<PathBuf>,
    }

    impl ExtractingFilesystemMounter {
        pub fn new() -> Self {
            Self {
                file_overrides: vec![],
                file_deletions: vec![],
            }
        }

        pub fn with_modifications(
            file_overrides: Vec<(PathBuf, Vec<u8>)>,
            file_deletions: Vec<PathBuf>,
        ) -> Self {
            Self {
                file_overrides,
                file_deletions,
            }
        }
    }

    #[async_trait]
    impl Mounter for ExtractingFilesystemMounter {
        async fn mount_range(
            &self,
            device: PathBuf,
            offset_bytes: u64,
            len_bytes: u64,
        ) -> Result<Box<dyn MountedPartition>> {
            async fn extract_partition<P: Partition>(
                device: &Path,
                offset_bytes: u64,
                len_bytes: u64,
                target: &Path,
            ) -> Result<()> {
                P::open_range(device.to_path_buf(), offset_bytes, len_bytes)
                    .await?
                    .copy_files_to(target)
                    .await
                    .context("Could not copy files to tempdir")
            }

            let target = TempDir::new().context("Could not create tempdir")?;

            // Try to extract as FAT first, then EXT
            if let Err(fat_err) =
                extract_partition::<FatPartition>(&device, offset_bytes, len_bytes, target.path())
                    .await
            {
                if let Err(ext_err) = extract_partition::<ExtPartition>(
                    &device,
                    offset_bytes,
                    len_bytes,
                    target.path(),
                )
                .await
                {
                    bail!(
                        "Could not open device as either FAT or EXT partition. \
                         FAT error: {fat_err}, EXT error: {ext_err}"
                    )
                }
            }

            // Apply test modifications
            for (path, new_content) in &self.file_overrides {
                let full_path = target.path().join(path);
                if full_path.exists() {
                    tokio::fs::write(&full_path, new_content).await?;
                }
            }

            for path in &self.file_deletions {
                let full_path = target.path().join(path);
                if full_path.exists() {
                    tokio::fs::remove_file(&full_path)
                        .await
                        .context("Could not delete file")?;
                }
            }

            Ok(Box::new(MockMount {
                mount_point: Arc::new(target),
            }))
        }
    }
}
