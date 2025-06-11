use anyhow::Result;
use std::path::Path;
use sys_mount::{Mount, MountBuilder, UnmountDrop, UnmountFlags};
use tempfile::TempDir;

pub struct TempMount {
    // The order of fields matters because the `mount` must be dropped before `target`.
    // According to the Rust spec, fields are dropped in the order of declaration.
    mount: UnmountDrop<Mount>,
    target: TempDir,
}

impl TempMount {
    pub fn from_mount_builder(
        mount_builder: MountBuilder,
        source: impl AsRef<Path>,
    ) -> Result<Self> {
        let target = TempDir::new()?;
        let mount = mount_builder.mount_autodrop(source, target.path(), UnmountFlags::empty())?;
        Ok(Self { mount, target })
    }

    pub fn target_path(&self) -> &Path {
        self.target.path()
    }
}
