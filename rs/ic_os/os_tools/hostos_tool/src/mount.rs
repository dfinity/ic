use anyhow::{Error, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use sys_mount::{Mount, MountFlags, UnmountDrop, UnmountFlags};
use tempfile::TempDir;

#[async_trait]
pub trait DeviceMounter: Send + Sync {
    async fn mount(
        &self,
        device: PathBuf,
        offset_bytes: u64,
        len_bytes: u64,
    ) -> Result<Box<dyn DeviceMount>>;
}

pub trait DeviceMount: Send + Sync {
    fn target_path(&self) -> &Path;
}

pub struct TempMount {
    // The order of fields matters because the `mount` must be dropped before `target`.
    // According to the Rust spec, fields are dropped in the order of declaration.
    mount: UnmountDrop<Mount>,
    _tempdir: TempDir,
}

impl DeviceMount for TempMount {
    fn target_path(&self) -> &Path {
        self.mount.target_path()
    }
}

pub struct TempMounter;

#[async_trait]
impl DeviceMounter for TempMounter {
    async fn mount(
        &self,
        device: PathBuf,
        offset_bytes: u64,
        _len_bytes: u64,
    ) -> Result<Box<dyn DeviceMount>> {
        let mount = tokio::task::spawn_blocking(move || {
            let tempdir = TempDir::new()?;
            let target = tempdir.path();
            Ok::<TempMount, Error>(TempMount {
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
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    pub struct TestMount {
        target: TempDir,
    }

    impl DeviceMount for TestMount {
        fn target_path(&self) -> &Path {
            self.target.path()
        }
    }

    pub struct TestMounter {
        overrides: Vec<(PathBuf, Vec<u8>)>,
        deletes: Vec<PathBuf>,
    }

    impl TestMounter {
        pub fn new() -> Self {
            Self {
                overrides: vec![],
                deletes: vec![],
            }
        }

        pub fn with_overrides(overrides: Vec<(PathBuf, Vec<u8>)>, deletes: Vec<PathBuf>) -> Self {
            Self { overrides, deletes }
        }
    }

    #[async_trait]
    impl DeviceMounter for TestMounter {
        async fn mount(
            &self,
            device: PathBuf,
            offset_bytes: u64,
            len_bytes: u64,
        ) -> Result<Box<dyn DeviceMount>> {
            async fn extract<P: Partition>(
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

            let target = TempDir::new().expect("Could not create tempdir");

            if let Err(fat_err) =
                extract::<FatPartition>(&device, offset_bytes, len_bytes, target.path()).await
            {
                if let Err(ext_err) =
                    extract::<ExtPartition>(&device, offset_bytes, len_bytes, target.path()).await
                {
                    bail!(
                        "Could not open device as either FAT or EXT partition. \
                         FAT error: {fat_err}, EXT error: {ext_err}"
                    )
                }
            }

            for (path, new_content) in &self.overrides {
                let path = target.path().join(path);
                if path.exists() {
                    tokio::fs::write(&path, new_content).await?;
                }
            }

            for path in &self.deletes {
                let path = target.path().join(path);
                if path.exists() {
                    tokio::fs::remove_file(&path)
                        .await
                        .context("Could not delete file")?;
                }
            }

            Ok(Box::new(TestMount { target }))
        }
    }
}
