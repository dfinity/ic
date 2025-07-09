use anyhow::{Context, Result};
use devicemapper::{DevId, DmFlags, DmName, DmOptions, Sectors, DM};
use loopdev::LoopDevice;
use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::{NamedTempFile, TempPath};

pub trait Device: Any {
    fn path(&self) -> &Path;
    fn len(&self) -> Sectors;
}

impl Device for MappedDevice {
    fn path(&self) -> &Path {
        &self.path
    }

    fn len(&self) -> Sectors {
        self.len
    }
}

/// Represents a linear segment for device mapping. A linear segment maps `sector_count` sectors
/// start at `start_sector` from `device`.
// #[derive(Debug)]
pub struct LinearSegment {
    pub source: Box<dyn Device>,
    pub start: Sectors,
    pub len: Sectors,
}

/// Copy-on-Write device using a temporary file and loop device
#[derive(Debug)]
pub struct CowDevice {
    device_path: PathBuf,
    loop_device: LoopDevice,
    _temp_file: TempPath,
}

impl CowDevice {
    pub fn new(size_bytes: u64) -> Result<Self> {
        let temp_file =
            NamedTempFile::new().context("Could not create temporary file for COW device")?;

        temp_file
            .as_file()
            .set_len(size_bytes)
            .context("Could not set size of COW backing file")?;

        let temp_path = temp_file.into_temp_path();

        let loop_device = loopdev::LoopControl::open()?.next_free()?;

        loop_device
            .attach_file(&temp_path)
            .context("COW loopback attach_file failed")?;

        let device_path = loop_device
            .path()
            .context("COW loopback device does not have a path")?;
        Ok(CowDevice {
            loop_device,
            device_path,
            _temp_file: temp_path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.device_path
    }
}

impl Drop for CowDevice {
    fn drop(&mut self) {
        let _ = self.loop_device.detach();
    }
}

/// Device mapper mapped device
// #[derive(Debug)]
pub struct MappedDevice {
    pub name: &'static str,
    pub path: PathBuf,
    pub len: Sectors,
    pub dependencies: Vec<Box<dyn Any>>,
    pub device_mapper: Arc<DM>,
}

impl MappedDevice {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Creates a linear device mapping from multiple segments
    pub fn create_linear(
        device_mapper: Arc<DM>,
        name: &'static str,
        segments: Vec<LinearSegment>,
        readonly: bool,
    ) -> Result<Self> {
        let mut table = Vec::new();
        let mut current_offset = 0;
        let mut dependencies = Vec::new();

        for segment in segments {
            table.push((
                current_offset,
                segment.len.0,
                "linear".to_string(),
                format!("{} {}", segment.source.path().display(), segment.start),
            ));
            current_offset += segment.len.0;

            dependencies.push(segment.source as Box<dyn Any>);
        }

        Self::create_for_table(device_mapper, name, &table, readonly, dependencies)
    }

    /// Creates a snapshot device from an origin device and COW device
    pub fn create_snapshot(
        device_mapper: Arc<DM>,
        name: &'static str,
        origin_device: impl Device,
        cow_device: CowDevice,
        readonly: bool,
    ) -> Result<Self> {
        let table = [(
            0,
            origin_device.len().0,
            "snapshot".to_string(),
            format!(
                "{} {} N 8",
                origin_device.path().display(),
                cow_device.path().display()
            ),
        )];

        Self::create_for_table(
            device_mapper,
            name,
            &table,
            readonly,
            vec![Box::new(origin_device), Box::new(cow_device)],
        )
    }

    /// Creates a snapshot-origin device from a source device
    pub fn create_snapshot_origin(
        device_mapper: Arc<DM>,
        name: &'static str,
        source_device: Box<dyn Device>,
        readonly: bool,
    ) -> Result<Self> {
        let table = [(
            0,
            source_device.len().0,
            "snapshot-origin".to_string(),
            source_device.path().display().to_string(),
        )];

        Self::create_for_table(
            device_mapper,
            name,
            &table,
            readonly,
            vec![source_device as Box<dyn Any>],
        )
    }

    fn create_for_table(
        device_mapper: Arc<DM>,
        name: &'static str,
        table: &[(u64, u64, String, String)],
        readonly: bool,
        dependencies: Vec<Box<dyn Any>>,
    ) -> Result<Self> {
        let dm_name = DmName::new(name).expect("Invalid DmName");

        let create_flags = if readonly {
            DmOptions::default().set_flags(DmFlags::DM_READONLY)
        } else {
            DmOptions::default()
        };

        device_mapper
            .device_create(dm_name, None, create_flags)
            .context("Failed to create mapped device")?;

        let len = Sectors(table.iter().map(|row| row.0 + row.1).max().unwrap_or(0));
        let device = MappedDevice {
            name,
            path: format!("/dev/mapper/{name}").into(),
            len,
            dependencies,
            device_mapper: device_mapper.clone(),
        };

        device_mapper
            .table_load(&DevId::Name(dm_name), table, DmOptions::default())
            .context("Failed to load device table")?;

        device_mapper
            .device_suspend(&DevId::Name(dm_name), DmOptions::default())
            .context("Failed to activate device")?;

        println!("Created device: {}", device.path.display());
        Ok(device)
    }
}

impl Drop for MappedDevice {
    fn drop(&mut self) {
        // if let Ok(device_mapper) = DM::new() {
        let _ = self.device_mapper.device_remove(
            &DevId::Name(DmName::new(self.name).unwrap()),
            DmOptions::default(),
        );
        // }
    }
}
