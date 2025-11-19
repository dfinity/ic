use crate::io::retry_if_busy;
use anyhow::{Context, Result, ensure};
use devicemapper::{
    DM, DevId, Device, DmName, DmOptions, LinearDevTargetParams, LinearDevTargetTable,
    LinearTargetParams, TargetLine, TargetTable, devnode_to_devno,
};
use loopdev::LoopDevice;
use nix::ioctl_read;
use std::fmt::Debug;
use std::fs::File;
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::{NamedTempFile, TempPath};

// Republish these types so clients can pass them as parameters.
pub use devicemapper::{Bytes, Sectors};

#[allow(clippy::len_without_is_empty)]
pub trait DeviceTrait: Send + Sync {
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
/// starting at `start` from `device`.
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
    pub fn prefix(device: Box<dyn DeviceTrait>, len: Sectors) -> Result<Self> {
        ensure!(len <= device.len(), "Length exceeds device size");
        Ok(Self {
            source: device,
            start: Sectors(0),
            len,
        })
    }

    /// Creates a linear segment that maps the device starting from `from`.
    pub fn suffix(device: Box<dyn DeviceTrait>, start: Sectors) -> Result<Self> {
        ensure!(start <= device.len(), "Start sector exceeds device size");
        let len = device.len() - start;
        Ok(Self {
            source: device,
            start,
            len,
        })
    }

    /// Creates a linear segment that maps `len` sectors starting at `start` from `device`.
    pub fn slice(device: Box<dyn DeviceTrait>, start: Sectors, len: Sectors) -> Result<Self> {
        ensure!(start + len <= device.len(), "Slice exceeds device size");
        Ok(Self {
            source: device,
            start,
            len,
        })
    }
}

/// Base devices are managed externally. The struct just holds information about the device.
#[derive(Clone)] // Clone just copies the device information, not the actual device.
pub struct BaseDevice {
    len: Sectors,
    device: Device,
}

impl BaseDevice {
    /// Creates a new BaseDevice from a block device file path.
    /// The device behind the path must be valid for the lifetime of the constructed object.
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

impl Drop for BaseDevice {
    fn drop(&mut self) {
        debug_assert_valid(self);
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
        let temp_file = NamedTempFile::with_prefix("temp_device")
            .context("Could not create temporary file for COW device")?;

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

        let loop_device = LoopDeviceWrapper::attach_to_next_free(&temp_path)
            .context("Temp loopback creation failed")?;

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

    pub fn path(&self) -> Option<PathBuf> {
        self._loop_device.path()
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
pub struct LoopDeviceWrapper(pub LoopDevice);

impl LoopDeviceWrapper {
    /// Opens a loop device and attaches it to the specified file.
    pub fn attach_to_next_free(path: &Path) -> Result<Self> {
        // next_free() will return the same loop device until a file is attached to it, so
        // it can happen that a parallel process gets the same loop device and attaches a file
        // to it before we do. In this case attach_file will fail with ResourceBusy.
        // We solve this by retrying the operation.
        retry_if_busy(|| {
            let loop_device = Self(loopdev::LoopControl::open()?.next_free()?);
            loop_device.attach_file(path)?;
            Ok(loop_device)
        })
        .context("Failed to attach loop device")
    }
}

impl Drop for LoopDeviceWrapper {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            if !std::thread::panicking() {
                let major = self.major().expect("Could not get major number");
                let minor = self.minor().expect("Could not get minor number");
                let backing_file_path = std::fs::read_to_string(format!(
                    "/sys/dev/block/{major}:{minor}/loop/backing_file"
                ))
                .expect("Could not read backing file from sysfs");

                assert!(
                    Path::new(backing_file_path.trim()).exists(),
                    "LoopDeviceWrapper backing file does not exist: {backing_file_path}"
                );
            }
        }

        if let Err(err) = self.0.detach() {
            debug_panic(&format!("Failed to detach loop device: {err}"));
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
    name: String,
    path: PathBuf,
    len: Sectors,
    device_mapper: Arc<DM>,
    device: Device,
    _dependencies: Vec<Box<dyn DeviceTrait>>,
}

impl Debug for MappedDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MappedDevice")
            .field("name", &self.name)
            .field("len", &self.len)
            .finish()
    }
}

impl MappedDevice {
    /// Creates a linear device mapping from multiple segments.
    /// Devices in `segments` must stay valid for the lifetime of the mapping.
    pub fn create_linear(
        device_mapper: Arc<DM>,
        name: &'static str,
        segments: Vec<LinearSegment>,
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
            &LinearDevTargetTable::new(table).to_raw_table(),
            current_offset,
            dependencies,
        )
    }

    /// Creates a non-persistent snapshot device with 8-sector chunks.
    /// `source` must stay valid for the lifetime of the snapshot.
    pub fn create_snapshot(
        device_mapper: Arc<DM>,
        name: &str,
        source: Box<dyn DeviceTrait>,
        copy_on_write: Box<dyn DeviceTrait>,
    ) -> Result<MappedDevice> {
        Self::create(
            device_mapper,
            name,
            &[(
                /*start=*/ 0,
                /*length=*/ source.len().0,
                "snapshot".to_string(),
                /*snapshot params, see dm-snapshot docs */
                format!("{} {} N 8", source.device(), copy_on_write.device()),
            )],
            source.len(),
            vec![source, copy_on_write],
        )
    }

    fn create(
        dm: Arc<DM>,
        name: &str,
        table: &[(u64, u64, String, String)],
        len: Sectors,
        dependencies: Vec<Box<dyn DeviceTrait>>,
    ) -> Result<MappedDevice> {
        let dm_name = DmName::new(name).expect("Illegal DmName");
        let device = dm
            .device_create(dm_name, None, DmOptions::default())
            .context("Failed to create mapped device")?;
        // Wrap the device right away by creating a MappedDevice so it gets detached in the
        // MappedDevice Drop impl if there is an error later.
        let mapped_device = MappedDevice {
            name: name.to_string(),
            path: format!("/dev/mapper/{name}").into(),
            device: device.device(),
            len,
            device_mapper: dm,
            _dependencies: dependencies,
        };

        mapped_device
            .device_mapper
            .table_load(&DevId::Name(dm_name), table, DmOptions::default())
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
        debug_assert_valid(self);

        if let Err(err) = self.device_mapper.device_remove(
            &DevId::Name(DmName::new(&self.name).unwrap()),
            DmOptions::default(),
        ) {
            debug_panic(&format!("Failed to remove device mapper device: {err}"));
        }
    }
}

fn debug_assert_valid(_device: &dyn DeviceTrait) {
    #[cfg(debug_assertions)]
    {
        if std::thread::panicking() {
            return;
        }
        let len: u64 = std::fs::read_to_string(format!("/sys/dev/block/{}/size", _device.device()))
            .expect("Could not read size from sysfs")
            .trim()
            .parse()
            .expect("Could not parse size");
        assert_eq!(
            len,
            _device.len().0,
            "Device {} has unexpected size",
            _device.device()
        );
    }
}

/// Prints a message to stderr and panics in debug builds if not already panicking.
fn debug_panic(msg: &str) {
    #[cfg(debug_assertions)]
    {
        if !std::thread::panicking() {
            panic!("{msg}");
        }
    }
    eprintln!("{msg}");
}
