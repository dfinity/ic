use anyhow::{bail, ensure, Context, Result};
use devicemapper::{DevId, DmFlags, DmName, DmOptions, DM};
use loopdev::LoopDevice;
use std::fmt::Debug;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::{NamedTempFile, TempPath};

const UPGRADE_DM_NAME: &'static str = "upgrade-guestos";
const READONLY_DATA_PARTITION_DM_NAME: &'static str = "ro-guestos-data";
const READONLY_DATA_PARTITION_SNAPSHOT_NAME: &'static str = "ro-guestos-data-snapshot";
const READONLY_DATA_PARTITION_SNAPSHOT_ORIGIN_NAME: &'static str =
    "ro-guestos-data-snapshot-origin";

const ALL_DM_NAMES_IN_CLEANUP_ORDER: [&'static str; 3] = [
    // UPGRADE_DM uses READONLY_DATA_PARTITION_DM so we need to clean them up in this order.
    UPGRADE_DM_NAME,
    READONLY_DATA_PARTITION_SNAPSHOT_ORIGIN_NAME,
    READONLY_DATA_PARTITION_DM_NAME,
];

/// Creates a mapped device for the Upgrade VM.
///
/// The mapped device has two segments:
///  - the first 9 partitions of the base device are read-write,
///  - writes to the last 10th partition of the base device are not propagated to the base device,
///    but are instead stored in a temporary snapshot file. This snapshot file is deleted
///    when the mapped device is dropped.
///
/// This setup ensures that the data partition of the guest which stores all data won't be
/// overwritten by the upgrade virtual machine.
pub fn create_mapped_device(base_device: &Path) -> Result<MappedUpgradeDevice> {
    if !base_device.exists() {
        bail!(
            "Base device does not exist at path: {}",
            base_device.display()
        );
    }

    let dev_mapper = DM::new().context("Failed to create device mapper instance")?;
    // Try to clean up existing devices.
    cleanup_devices(&dev_mapper);

    let base_device = base_device
        .canonicalize()
        .context("Could not canonicalize base device path")?;

    let gpt = gpt::disk::read_disk(&base_device).context("Could not read GPT from device")?;
    ensure!(
        gpt.partitions().len() == 10,
        "Expected guest device to have 10 partitions but only found {}",
        gpt.partitions().len()
    );
    let data_partition = gpt
        .partitions()
        .get(&10)
        .context("Could not find partition 10")?;

    println!("LBS: {}", gpt.logical_block_size().as_u64());

    let DEVICE_SIZE_SECTORS = 61649264640; // FIXME.

    dbg!(data_partition.first_lba);

    let data_partition_sector_count = DEVICE_SIZE_SECTORS - data_partition.first_lba;
    // let data_partition_sector_count = data_partition
    //     .sectors_len()
    //     .context("Could not get length of data partition")?;

    let data_partition_device = MappedDevice::create_for_table(
        &dev_mapper,
        READONLY_DATA_PARTITION_DM_NAME,
        &[(
            0,
            data_partition_sector_count,
            "linear".to_string(),
            format!("{} {}", base_device.display(), data_partition.first_lba),
        )],
        /*readonly=*/ true,
        vec![],
    )
    .context("Failed to create data_partition_device")?;

    let cow_temp_file =
        NamedTempFile::new().context("Could not create temporary file for COW device")?;
    cow_temp_file
        .as_file()
        .set_len(128 * 1024 * 1024)
        .context("Could not set size of COW backing file")?;
    let cow_temp_path = cow_temp_file.into_temp_path();
    let cow_loop_device = loopdev::LoopControl::open()?.next_free()?;
    cow_loop_device
        .attach_file(&cow_temp_path)
        .context("COW loopback attach_file failed")?;
    // Wrap the loopback device in a wrapper that detaches the file from the device when dropped.
    let cow_loop_device = LoopDeviceWrapper::from(cow_loop_device);

    let data_partition_snapshot_origin_device = MappedDevice::create_for_table(
        &dev_mapper,
        READONLY_DATA_PARTITION_SNAPSHOT_ORIGIN_NAME,
        &[(
            0,
            data_partition_sector_count,
            "snapshot-origin".to_string(),
            data_partition_device.path.display().to_string(),
        )],
        /*readonly=*/ true,
        vec![Arc::new(data_partition_device)],
    )?;

    let data_partition_snapshot_device = MappedDevice::create_for_table(
        &dev_mapper,
        READONLY_DATA_PARTITION_SNAPSHOT_NAME,
        &[(
            0,
            data_partition_sector_count,
            "snapshot".to_string(),
            // The snapshot target's parameters are:
            // <origin_device> <cow_device> <persistence> <chunk_size>
            format!(
                "{} {} N 8",
                data_partition_snapshot_origin_device.path.display(),
                cow_loop_device
                    .path()
                    .context("Could not get path of COW loopback device")?
                    .display(),
            ),
        )],
        /*readonly=*/ true,
        vec![Arc::new(data_partition_snapshot_origin_device)],
    )
    .context("Failed to create data_partition_device")?;

    let mapping = [
        // Target 1: Read-write section using a linear mapping.
        (
            0,
            data_partition.first_lba,
            "linear".to_string(),
            format!("{} 0", base_device.display()),
        ),
        // Target 2: Read-only section using a snapshot.
        (
            data_partition.first_lba,
            data_partition_sector_count,
            "linear".to_string(),
            format!("{} 0", data_partition_snapshot_device.path.display()),
        ),
    ];

    dbg!(&mapping);

    let upgrade_device = MappedDevice::create_for_table(
        &dev_mapper,
        UPGRADE_DM_NAME,
        &mapping,
        /*readonly=*/ false,
        vec![Arc::new(data_partition_snapshot_device)],
    )
    .context("Failed to create upgrade_device")?;

    // std::thread::sleep(std::time::Duration::from_secs(60));

    Ok(MappedUpgradeDevice {
        // _data_partition_device: data_partition_device,
        _upgrade_device: upgrade_device,
        _cow_loop_device: cow_loop_device,
        // _cow_temp_file: cow_temp_file,
        _cow_temp_file: cow_temp_path,
    })
}

fn x() -> Box<dyn AsRef<Path>> {
    Box::new(PathBuf::new())
}

fn y() {
    let x = x().deref().as_ref();
}

fn cleanup_devices(dev_mapper: &DM) {
    let devices = match dev_mapper.list_devices() {
        Ok(devices) => devices,
        Err(err) => {
            eprintln!("Failed to list devices: {}", err);
            return;
        }
    };

    let existing_devices: Vec<_> = devices.into_iter().map(|(name, ..)| name).collect();

    ALL_DM_NAMES_IN_CLEANUP_ORDER
        .iter()
        .filter_map(|name| {
            existing_devices
                .iter()
                .find(|existing| existing.as_bytes() == name.as_bytes())
        })
        .for_each(|name| try_remove_device(dev_mapper, name));
}

fn try_remove_device(dev_mapper: &DM, name: &DmName) {
    let mut retries = 10;
    loop {
        if let Err(err) = dev_mapper.device_remove(&DevId::Name(name), DmOptions::default()) {
            eprintln!("Failed to remove device {}: {}", name, err);
            retries -= 1;
            if retries == 0 {
                break;
            }
            println!("Retrying in 5 seconds...");
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    }
}

#[derive(Debug)]
struct MappedDevice {
    name: &'static str,
    path: PathBuf,
    dependencies: Vec<Arc<MappedDevice>>,
}

impl MappedDevice {
    fn create_for_table(
        dev_mapper: &DM,
        name: &'static str,
        table: &[(u64, u64, String, String)],
        readonly: bool,
        dependencies: Vec<Arc<MappedDevice>>,
    ) -> Result<Self> {
        let dm_name = DmName::new(name).expect("Invalid DmName");

        let create_flags = if readonly {
            DmOptions::default().set_flags(DmFlags::DM_READONLY)
        } else {
            DmOptions::default()
        };
        dev_mapper
            .device_create(dm_name, None, create_flags)
            .context("Failed to create mapped device")?;
        let mapped_device = MappedDevice {
            name,
            path: format!("/dev/mapper/{name}").into(),
            dependencies,
        };
        dev_mapper
            .table_load(&DevId::Name(dm_name), table, DmOptions::default())
            .context("Failed to load device table")?;
        // The name is confusing, it actually activates the device.
        dev_mapper.device_suspend(&DevId::Name(dm_name), DmOptions::default())?;

        println!("Created: {}", mapped_device.path.display());
        // std::thread::sleep(std::time::Duration::from_secs(30));
        Ok(mapped_device)
    }
}

impl Drop for MappedDevice {
    fn drop(&mut self) {
        if let Ok(dev_mapper) = DM::new() {
            let _ = dev_mapper.device_remove(
                &DevId::Name(DmName::new(self.name).unwrap()),
                DmOptions::default(),
            );
        }
    }
}

/// A mapped device. The device is removed when this struct is dropped.
#[derive(Debug)]
pub struct MappedUpgradeDevice {
    // The order of these fields is important. They are dropped in the declaration order.
    // Upgrade device uses data partition device and cow loop device.
    // Cow loop device uses cow temp file.
    _upgrade_device: MappedDevice,
    // _data_partition_device: MappedDevice,
    _cow_loop_device: LoopDeviceWrapper,
    // _cow_temp_file: NamedTempFile,
    _cow_temp_file: TempPath,
}

impl MappedUpgradeDevice {
    pub fn path(&self) -> &Path {
        &self._upgrade_device.path
    }
}

#[derive(Debug)]
struct LoopDeviceWrapper(LoopDevice);

impl From<LoopDevice> for LoopDeviceWrapper {
    fn from(loop_device: LoopDevice) -> Self {
        Self(loop_device)
    }
}

impl Drop for LoopDeviceWrapper {
    fn drop(&mut self) {
        let _ignore = self.0.detach();
    }
}

impl Deref for LoopDeviceWrapper {
    type Target = LoopDevice;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
