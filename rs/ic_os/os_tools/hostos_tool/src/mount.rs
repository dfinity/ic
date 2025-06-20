use anyhow::{Context, Error, Result};
use async_trait::async_trait;
use gpt::GptDisk;
use std::fs::File;
use std::path::{Path, PathBuf};
use sys_mount::FilesystemType;
#[cfg(target_os = "linux")]
use sys_mount::{Mount, MountFlags, UnmountDrop, UnmountFlags};
use tempfile::TempDir;
use uuid::Uuid;

// There are two traits here:
// 1. PartitionProvider (high level): provides access to partitions by UUID
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

/// Trait for accessing partitions by UUID from a device
#[async_trait]
pub trait PartitionProvider: Send + Sync {
    /// Mounts a partition by its UUID with specified mount options.
    ///
    /// # Arguments
    /// * `partition_uuid` - UUID of the partition to mount
    /// * `options` - Mount options like read-only flag
    ///
    /// # Returns
    /// A boxed MountedPartition trait object that provides access to the mounted filesystem.
    /// The mount is automatically cleaned up when the returned object is dropped.
    async fn mount_partition(
        &self,
        partition_uuid: Uuid,
        options: MountOptions,
    ) -> Result<Box<dyn MountedPartition>>;
}

/// Handles mounting raw device ranges (offset + length) to filesystem paths
#[async_trait]
pub trait Mounter: Send + Sync {
    /// Mounts a range of bytes from a block device to a filesystem path.
    ///
    /// # Arguments
    /// * `device` - Path to the block device containing the filesystem
    /// * `offset_bytes` - Offset in bytes where the filesystem starts within the device
    /// * `len_bytes` - Length of the filesystem in bytes
    /// * `options` - Mount options like read-only flag
    ///
    /// # Returns
    /// A boxed MountedPartition trait object that provides access to the mounted filesystem.
    /// The mount is automatically cleaned up when the returned object is dropped.
    async fn mount_range(
        &self,
        device: PathBuf,
        offset_bytes: u64,
        len_bytes: u64,
        options: MountOptions,
    ) -> Result<Box<dyn MountedPartition>>;
}

#[derive(Copy, Clone)]
pub enum FileSystem {
    Vfat,
    Ext4,
}

impl FileSystem {
    /// Returns the filesystem name as a string accepted by the mount syscall
    fn as_str(&self) -> &'static str {
        match self {
            FileSystem::Vfat => "vfat",
            FileSystem::Ext4 => "ext4",
        }
    }
}

#[derive(Copy, Clone)]
pub struct MountOptions {
    /// Whether to mount the partition read-only
    pub readonly: bool,

    pub file_system: FileSystem,
}

/// Represents a mounted partition with access to its filesystem.
/// `MountedPartition` uses RAII to represent the mount. Dropping the object cleans up the mount.
pub trait MountedPartition: Send + Sync {
    fn mount_point(&self) -> &Path;
}

/// GPT-aware partition provider that can mount partitions by UUID
pub struct GptPartitionProvider {
    device: PathBuf,
    gpt: GptDisk<File>,
    mounter: Box<dyn Mounter>,
}

impl GptPartitionProvider {
    pub fn new(device: PathBuf) -> Result<Self> {
        #[cfg(target_os = "linux")]
        return Self::with_mounter(device, Box::new(LoopDeviceMounter));

        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("This only works on Linux.")
    }

    pub fn with_mounter(device: PathBuf, mounter: Box<dyn Mounter>) -> Result<Self> {
        let gpt = gpt::disk::read_disk(&device).context("Could not read GPT from device")?;
        Ok(Self {
            device,
            gpt,
            mounter,
        })
    }
}

#[async_trait]
impl PartitionProvider for GptPartitionProvider {
    async fn mount_partition(
        &self,
        partition_uuid: Uuid,
        options: MountOptions,
    ) -> Result<Box<dyn MountedPartition>> {
        let partition = self
            .gpt
            .partitions()
            .iter()
            .map(|(_, partition)| partition)
            .find(|partition| partition.part_guid == partition_uuid)
            .with_context(|| format!("Could not find partition {partition_uuid}"))?;

        let offset_bytes = partition.bytes_start(*self.gpt.logical_block_size())?;
        let len_bytes = partition.bytes_len(*self.gpt.logical_block_size())?;

        self.mounter
            .mount_range(self.device.clone(), offset_bytes, len_bytes, options)
            .await
    }
}

/// Real filesystem mount using system mount with loop device
#[cfg(target_os = "linux")]
struct LoopDeviceMount {
    // Field order matters: mount must be dropped before tempdir
    // According to the Rust spec, fields are dropped in the order of declaration.
    mount: UnmountDrop<Mount>,
    _tempdir: TempDir,
}

#[cfg(target_os = "linux")]
impl MountedPartition for LoopDeviceMount {
    fn mount_point(&self) -> &Path {
        self.mount.target_path()
    }
}

/// Production filesystem mounter using real system mounts
#[cfg(target_os = "linux")]
pub struct LoopDeviceMounter;

#[cfg(target_os = "linux")]
#[async_trait]
impl Mounter for LoopDeviceMounter {
    async fn mount_range(
        &self,
        device: PathBuf,
        offset_bytes: u64,
        _len_bytes: u64,
        options: MountOptions,
    ) -> Result<Box<dyn MountedPartition>> {
        let mount = tokio::task::spawn_blocking(move || {
            let tempdir = TempDir::new()?;
            let target = tempdir.path();
            Ok::<LoopDeviceMount, Error>(LoopDeviceMount {
                mount: Mount::builder()
                    .fstype(FilesystemType::Manual(options.file_system.as_str()))
                    .loopback_offset(offset_bytes)
                    .flags(if options.readonly {
                        MountFlags::RDONLY
                    } else {
                        MountFlags::empty()
                    })
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
    use anyhow::{ensure, Context};
    use partition_tools::ext::ExtPartition;
    use partition_tools::fat::FatPartition;
    use partition_tools::Partition;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::process::Command;

    /// Test partition provider that uses pre-populated directories
    pub struct MockPartitionProvider {
        pub partitions: HashMap<Uuid, Arc<TempDir>>,
    }

    impl MockPartitionProvider {
        pub fn new(partitions: HashMap<Uuid, Arc<TempDir>>) -> Self {
            Self { partitions }
        }
    }

    #[async_trait]
    impl PartitionProvider for MockPartitionProvider {
        async fn mount_partition(
            &self,
            partition_uuid: Uuid,
            options: MountOptions,
        ) -> Result<Box<dyn MountedPartition>> {
            let partition_dir = self
                .partitions
                .get(&partition_uuid)
                .with_context(|| format!("Could not find partition {partition_uuid}"))?;

            if options.readonly {
                ensure!(
                    Command::new("chmod")
                        .arg("-R")
                        .arg("-w")
                        .arg(partition_dir.path())
                        .status()
                        .await?
                        .success(),
                    "Could not chmod directory"
                );
            }

            Ok(Box::new(MockMount {
                mount_point: partition_dir.clone(),
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
    pub struct ExtractingFilesystemMounter;

    #[async_trait]
    impl Mounter for ExtractingFilesystemMounter {
        async fn mount_range(
            &self,
            device: PathBuf,
            offset_bytes: u64,
            len_bytes: u64,
            options: MountOptions,
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

            let extraction_dir = TempDir::new().context("Could not create tempdir")?;

            match options.file_system {
                FileSystem::Vfat => {
                    extract_partition::<FatPartition>(
                        &device,
                        offset_bytes,
                        len_bytes,
                        extraction_dir.path(),
                    )
                    .await?
                }
                FileSystem::Ext4 => {
                    extract_partition::<ExtPartition>(
                        &device,
                        offset_bytes,
                        len_bytes,
                        extraction_dir.path(),
                    )
                    .await?
                }
            };

            if options.readonly {
                ensure!(
                    Command::new("chmod")
                        .arg("-R")
                        .arg("-w")
                        .arg(extraction_dir.path())
                        .status()
                        .await?
                        .success(),
                    "Could not chmod directory"
                );
            }

            Ok(Box::new(MockMount {
                mount_point: Arc::new(extraction_dir),
            }))
        }
    }
}
