use anyhow::{Context, Result};
use devicemapper::{
    devnode_to_devno, Bytes, CacheDevTargetTable, CacheTargetParams, DevId, Device, DmFlags,
    DmName, DmOptions, LinearDevTargetParams, LinearDevTargetTable, LinearTargetParams, Sectors,
    TargetLine, TargetTable, DM,
};
use loopdev::LoopDevice;
use nix::ioctl_read;
use std::any::Any;
use std::fs::File;
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::{NamedTempFile, TempPath};

pub trait DeviceTrait: Any {
    fn len(&self) -> Sectors;
    fn device(&self) -> Device;
}

impl DeviceTrait for MappedDevice {
    fn len(&self) -> Sectors {
        self.len
    }

    fn device(&self) -> Device {
        self.device
    }
}

/// Represents a linear segment for device mapping. A linear segment maps `len` sectors
/// start at `start` from `device`.
pub struct LinearSegment {
    source: Box<dyn DeviceTrait>,
    start: Sectors,
    len: Sectors,
}

impl LinearSegment {
    /// Creates a linear segment that maps the entire device.
    pub fn full(device: Box<dyn DeviceTrait>) -> Self {
        let len = device.len();
        Self {
            source: device,
            start: Sectors(0),
            len,
        }
    }

    /// Creates a linear segment that maps the first `len` sectors of `device`.
    pub fn prefix(device: Box<dyn DeviceTrait>, len: Sectors) -> Self {
        Self {
            source: device,
            start: Sectors(0),
            len,
        }
    }

    /// Creates a linear segment that maps the device starting from `from`.
    pub fn suffix(device: Box<dyn DeviceTrait>, start: Sectors) -> Self {
        let len = device.len() - start;
        Self {
            source: device,
            start,
            len,
        }
    }

    /// Creates a linear segment that maps `len` sectors starting at `start` from `device`.
    pub fn slice(device: Box<dyn DeviceTrait>, start: Sectors, len: Sectors) -> Self {
        Self {
            source: device,
            start,
            len,
        }
    }
}

/// Base devices are managed externally. The struct just holds information about the device.
#[derive(Copy, Clone)]
pub struct BaseDevice {
    len: Sectors,
    device: Device,
}

impl BaseDevice {
    pub fn from_path(path: &Path) -> Result<Self> {
        let device_len = Self::get_device_len(path).context("Could not get block device size")?;
        let device = devnode_to_devno(path)
            .context("Could not get devno")?
            .context("Device does not seem to exist")?
            .into();
        Ok(Self {
            len: device_len,
            device,
        })
    }

    /// Get the size of a given block device file
    fn get_device_len(device: &Path) -> Result<Sectors> {
        // I didn't find a higher level approach for this, so I'm just using the ioctl directly
        // (0x12, 96) corresponds to BLKGETSIZE64
        // see linux/include/uapi/linux/fs.h
        ioctl_read!(blkgetsize64, 0x12, 114, u64);

        let file = File::open(device).context("Could not open device")?;
        let mut val = 0;
        unsafe { blkgetsize64(file.as_raw_fd(), &mut val) }.context("blkgetsize64 failed")?;
        Ok(Bytes(val as u128).sectors())
    }
}

impl DeviceTrait for BaseDevice {
    fn len(&self) -> Sectors {
        self.len
    }

    fn device(&self) -> Device {
        self.device
    }
}

/// A loop device backed by a temporary file. When dropped, the loop device is detached and the
/// backing file is deleted.
pub struct TempDevice {
    len: Sectors,
    device: Device,
    // The declaration order is important, the loop device must be dropped before the backing file.
    _loop_device: LoopDeviceWrapper,
    _temp_file: TempPath,
}

impl TempDevice {
    pub fn new(len: Sectors) -> Result<Self> {
        let temp_file =
            NamedTempFile::new().context("Could not create temporary file for COW device")?;

        temp_file
            .as_file()
            .set_len(
                len.bytes()
                    .0
                    .try_into()
                    .context("len does not fit into u64")?,
            )
            .context("Could not set size of backing file")?;

        let temp_path = temp_file.into_temp_path();

        let loop_device = LoopDeviceWrapper(loopdev::LoopControl::open()?.next_free()?);
        loop_device
            .attach_file(&temp_path)
            .context("Temp loopback attach_file failed")?;

        let minor = loop_device
            .minor()
            .context("Could not query loop device minor number")?;
        let major = loop_device
            .major()
            .context("Could not query loop device major number")?;

        Ok(TempDevice {
            _loop_device: loop_device,
            len,
            device: Device { major, minor },
            _temp_file: temp_path,
        })
    }
}

impl DeviceTrait for TempDevice {
    fn len(&self) -> Sectors {
        self.len
    }

    fn device(&self) -> Device {
        self.device
    }
}

/// Wrapper around a loop device that automatically detaches it when dropped.
struct LoopDeviceWrapper(LoopDevice);

impl Drop for LoopDeviceWrapper {
    fn drop(&mut self) {
        if let Err(err) = self.0.detach() {
            eprintln!("Failed to detach loop device: {err}");
        }
    }
}

impl Deref for LoopDeviceWrapper {
    type Target = LoopDevice;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A device mapped by the device mapper.
/// The lifecycle of [MappedDevice] is managed by the owning process.
/// When a [MappedDevice] goes out of scope, it's removed from the device mapper. It can have
/// dependencies, these are other devices that the [MappedDevice] depends on and should be cleaned
/// up when the [MappedDevice] is dropped.
pub struct MappedDevice {
    name: &'static str,
    path: PathBuf,
    len: Sectors,
    device_mapper: Arc<DM>,
    device: Device,
    _dependencies: Vec<Box<dyn Any>>,
}

impl MappedDevice {
    /// Creates a linear device mapping from multiple segments.
    pub fn create_linear(
        device_mapper: Arc<DM>,
        name: &'static str,
        segments: Vec<LinearSegment>,
        readonly: bool,
    ) -> Result<Self> {
        let mut table = Vec::with_capacity(segments.len());
        let mut current_offset = Sectors(0);
        let mut dependencies = Vec::new();

        for segment in segments {
            table.push(TargetLine::new(
                current_offset,
                segment.len,
                LinearDevTargetParams::Linear(LinearTargetParams::new(
                    segment.source.device(),
                    segment.start,
                )),
            ));
            current_offset += segment.len;

            dependencies.push(segment.source as _);
        }

        Self::create(
            device_mapper,
            name,
            &LinearDevTargetTable::new(table),
            current_offset,
            readonly,
            dependencies,
        )
    }

    /// Creates a mapped device that reads from `origin` or `cache` and writes to `cache` only.
    pub fn create_writeback_cache(
        device_mapper: Arc<DM>,
        name: &'static str,
        metadata: Box<dyn DeviceTrait>,
        cache: Box<dyn DeviceTrait>,
        origin: Box<dyn DeviceTrait>,
        readonly: bool,
    ) -> Result<MappedDevice> {
        let len = origin.len();
        let params = CacheDevTargetTable::new(
            Sectors(0),
            origin.len(),
            CacheTargetParams::new(
                metadata.device(),
                cache.device(),
                origin.device(),
                Sectors(512),
                // writeback: a write to a block that is cached will go only to the cache and the
                // block will be marked dirty in the metadata.
                vec!["writeback".to_string()],
                "default".to_string(),
                vec![],
            ),
        );
        Self::create(
            device_mapper,
            name,
            &params,
            len,
            readonly,
            vec![origin, cache, metadata],
        )
    }

    fn create(
        dm: Arc<DM>,
        name: &'static str,
        table: &impl TargetTable,
        len: Sectors,
        readonly: bool,
        dependencies: Vec<Box<dyn Any>>,
    ) -> Result<MappedDevice> {
        let options = if readonly {
            DmOptions::default().set_flags(DmFlags::DM_READONLY)
        } else {
            DmOptions::default()
        };
        let dm_name = DmName::new(name).expect("Illegal DmName");
        let device = dm
            .device_create(dm_name, None, options)
            .context("Failed to create mapped device")?;
        // Wrap the device right away so it gets detached in the MappedDevice Drop impl if there
        // is an error later.
        let mapped_device = MappedDevice {
            name,
            path: format!("/dev/mapper/{name}").into(),
            device: device.device(),
            len,
            device_mapper: dm,
            _dependencies: dependencies,
        };

        mapped_device
            .device_mapper
            .table_load(
                &DevId::Name(dm_name),
                &table.to_raw_table(),
                DmOptions::default(),
            )
            .context("Failed to load device table")?;

        // The name is somewhat confusing, this activates the device.
        mapped_device
            .device_mapper
            .device_suspend(&DevId::Name(dm_name), DmOptions::default())?;

        Ok(mapped_device)
    }

    /// Returns the device path
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for MappedDevice {
    fn drop(&mut self) {
        if let Err(err) = self.device_mapper.device_remove(
            &DevId::Name(DmName::new(self.name).unwrap()),
            DmOptions::default(),
        ) {
            eprintln!("Failed to remove device mapper device: {err}");
        }
    }
}
