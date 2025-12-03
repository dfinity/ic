use crate::io::retry_if_busy;
use anyhow::{Context, Error, Result};
use async_trait::async_trait;
use gpt::GptDisk;
use std::fs::File;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use sys_mount::{FilesystemType, Mount, MountFlags, Unmount, UnmountFlags};
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
    /// Creates a new [GptPartitionProvider] for the given device.
    /// The `device` must be a block device or a disk image with a valid GPT partition table and
    /// must be valid for the entire lifetime of the constructed object.
    pub fn new(device: PathBuf) -> Result<Self> {
        #[cfg(target_os = "linux")]
        return Self::with_mounter(device, Box::new(LoopDeviceMounter));

        #[cfg(not(target_os = "linux"))]
        anyhow::bail!("This only works on Linux.")
    }

    pub fn with_mounter(device: PathBuf, mounter: Box<dyn Mounter>) -> Result<Self> {
        let gpt = gpt::disk::read_disk(&device)
            .with_context(|| format!("Could not read GPT from device {}", device.display()))?;
        Ok(Self {
            device,
            gpt,
            mounter,
        })
    }
}

impl Drop for GptPartitionProvider {
    fn drop(&mut self) {
        debug_assert!(
            self.device.exists(),
            "Device {} does not exist",
            self.device.display()
        );
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
            .values()
            .find(|partition| partition.part_guid == partition_uuid)
            .with_context(|| format!("Could not find partition {partition_uuid}"))?;

        let offset_bytes = partition.bytes_start(*self.gpt.logical_block_size())?;
        let len_bytes = partition.bytes_len(*self.gpt.logical_block_size())?;

        self.mounter
            .mount_range(self.device.clone(), offset_bytes, len_bytes, options)
            .await
            .context("mount_range failed")
    }
}

/// Real filesystem mount using system mount with loop device
#[cfg(target_os = "linux")]
struct LoopDeviceMount {
    // mount must be cleaned up before tempdir!
    //
    // We follow this in our Drop impl, but still stick to the Rust spec for
    // drop order as well. According to the spec, fields are dropped in the
    // order of declaration.
    mount: Mount,
    _tempdir: TempDir,
}

impl Drop for LoopDeviceMount {
    fn drop(&mut self) {
        if let Err(e) = retry_if_busy(|| self.mount.unmount(UnmountFlags::empty())) {
            // If umount fails, we need to avoid cleaning the tmpdir, as this
            // will purge the contents of the mounted fs, instead.
            eprintln!("Error dropping mount: {e:?}");
            self._tempdir.disable_cleanup(true);
        }
    }
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
            let mount_point = tempdir.path();
            Ok::<LoopDeviceMount, Error>(LoopDeviceMount {
                mount: retry_if_busy(|| {
                    Mount::builder()
                        .fstype(FilesystemType::Manual(options.file_system.as_str()))
                        .loopback_offset(offset_bytes)
                        .flags(MountFlags::empty())
                        .explicit_loopback()
                        .mount(&device, mount_point)
                })
                .context("Failed to create mount")?,
                _tempdir: tempdir,
            })
        })
        .await??;
        Ok(Box::new(mount))
    }
}

pub mod testing {
    use super::*;
    use anyhow::Context;
    use partition_tools::Partition;
    use partition_tools::ext::ExtPartition;
    use partition_tools::fat::FatPartition;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tempfile::TempDir;

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
            _options: MountOptions,
        ) -> Result<Box<dyn MountedPartition>> {
            let partition_dir = self
                .partitions
                .get(&partition_uuid)
                .with_context(|| format!("Could not find partition {partition_uuid}"))?;

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

    /// Map (device, offset, len) -> TempDir
    type PartitionMap = HashMap<(PathBuf, u64, u64), Arc<TempDir>>;

    /// Filesystem mounter for testing that extracts partition contents to temp directories.
    /// This is an alternative to real filesystem mounts when mounts are not possible (e.g. limited
    /// permissions in tests).
    ///
    /// The mounter "remembers" the extracted partitions, so extracting the same device/offset/len
    /// always returns the same directory.
    #[derive(Clone, Default)]
    pub struct ExtractingFilesystemMounter {
        #[allow(clippy::disallowed_types)] // Using tokio Mutex in testing is fine.
        mounts: Arc<tokio::sync::Mutex<PartitionMap>>,
    }

    #[async_trait]
    impl Mounter for ExtractingFilesystemMounter {
        async fn mount_range(
            &self,
            device: PathBuf,
            offset_bytes: u64,
            len_bytes: u64,
            options: MountOptions,
        ) -> Result<Box<dyn MountedPartition>> {
            let key = (device.clone(), offset_bytes, len_bytes);
            let mut mounts = self.mounts.lock().await;
            if !mounts.contains_key(&key) {
                mounts.insert(
                    key.clone(),
                    self.extract_partition_to_tempdir(
                        device.clone(),
                        offset_bytes,
                        len_bytes,
                        options,
                    )?,
                );
            }

            Ok(Box::new(MockMount {
                mount_point: mounts.get(&key).unwrap().clone(),
            }))
        }
    }

    impl ExtractingFilesystemMounter {
        fn extract_partition_to_tempdir(
            &self,
            device: PathBuf,
            offset_bytes: u64,
            len_bytes: u64,
            options: MountOptions,
        ) -> Result<Arc<TempDir>> {
            fn extract_partition<P: Partition>(
                device: &Path,
                offset_bytes: u64,
                len_bytes: u64,
                target: &Path,
            ) -> Result<()> {
                P::open_range(device.to_path_buf(), offset_bytes, len_bytes)?
                    .copy_files_to(target)
                    .context("Could not copy files to tempdir")
            }

            let extraction_dir = TempDir::new().context("Could not create tempdir")?;

            match options.file_system {
                FileSystem::Vfat => extract_partition::<FatPartition>(
                    &device,
                    offset_bytes,
                    len_bytes,
                    extraction_dir.path(),
                ),
                FileSystem::Ext4 => extract_partition::<ExtPartition>(
                    &device,
                    offset_bytes,
                    len_bytes,
                    extraction_dir.path(),
                ),
            }
            .context(format!(
                "Could not extract partition to {}",
                extraction_dir.path().display()
            ))?;

            Ok(Arc::new(extraction_dir))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use std::io::Write;
    use std::process::Command;
    use tempfile::NamedTempFile;

    fn create_test_image() -> Result<NamedTempFile> {
        let out = NamedTempFile::new()?;
        out.as_file().set_len(16 * 1024 * 1024)?;
        let temp_dir = TempDir::new()?;
        write!(File::create(temp_dir.path().join("foo.txt"))?, "hello")?;

        ensure!(
            Command::new("/usr/sbin/mkfs.ext4")
                .arg(out.path())
                .arg("-d")
                .arg(temp_dir.path())
                .status()
                .context("Could not start mkfs.ext4")?
                .success(),
            "mkfs.ext4 failed"
        );

        Ok(out)
    }

    #[tokio::test]
    async fn test_loop_device_mount_drop_with_unmount_failure() {
        let image = create_test_image().unwrap();

        let mount = LoopDeviceMounter
            .mount_range(
                image.path().to_path_buf(),
                0,
                0,
                MountOptions {
                    file_system: FileSystem::Ext4,
                },
            )
            .await
            .unwrap();

        let mount_point = mount.mount_point().to_path_buf();
        // Force unmount to fail by keeping a file handle open
        let _file = File::open(mount_point.join("foo.txt")).unwrap();

        drop(mount);

        assert!(mount_point.join("foo.txt").exists());
    }
}
