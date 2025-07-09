use crate::device_mapping::{CowDevice, Device, LinearSegment, MappedDevice};
use anyhow::{bail, ensure, Context, Result};
use devicemapper::{
    devnode_to_devno, Bytes, DevId, DmName, DmOptions, FlakeyTargetParams, LinearDev,
    LinearDevTargetParams, LinearTargetParams, Sectors, TargetLine, DM,
};
use nix::ioctl_read;
use std::fmt::Debug;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const UPGRADE_DM_NAME: &'static str = "upgrade-guestos";
const DATA_PARTITION_DM_NAME: &'static str = "guestos-data";
const DATA_PARTITION_SNAPSHOT_NAME: &'static str = "guestos-data-snapshot";
const DATA_PARTITION_SNAPSHOT_ORIGIN_NAME: &'static str = "guestos-data-snapshot-origin";

const ALL_DM_NAMES_IN_CLEANUP_ORDER: [&'static str; 4] = [
    UPGRADE_DM_NAME,
    DATA_PARTITION_SNAPSHOT_NAME,
    DATA_PARTITION_SNAPSHOT_ORIGIN_NAME,
    DATA_PARTITION_DM_NAME,
];

/// get the size of a given block device file
fn blkdev_size(device: &Path) -> Result<Sectors> {
    // I didn't find a higher level approach for this, so I'm just using the ioctl directly
    // (0x12, 96) corresponds to BLKGETSIZE
    // see linux/include/uapi/linux/fs.h
    ioctl_read!(blkgetsize, 0x12, 96, u64);

    let file = File::open(device).context("Could not open device")?;
    let mut val: u64 = 0;
    unsafe { blkgetsize(file.as_raw_fd(), &mut val) }.context("blkgetsize failed")?;
    Ok(Sectors(val))
}

struct BaseDevice {
    path: PathBuf,
    len: Sectors,
}

impl BaseDevice {
    // pub fn new(path: PathBuf) -> Result<Self> {
    //     let device_len = blkdev_size(&path).context("Could not get block device size")?;
    //     // devicemapper::DmDevice
    //     // let metadata = std::fs::metadata(path).context("Could not get metadata for base device")?;
    //     // let len_sectors = metadata.len() / 512;
    //     // Ok(Self {
    //     //     path: path.to_path_buf(),
    //     //     len: len_sectors,
    //     // })
    // }
}

impl Device for BaseDevice {
    fn path(&self) -> &Path {
        &self.path
    }

    fn len(&self) -> Sectors {
        self.len
    }
}

/// Creates a mapped device for the Upgrade VM
pub fn create_mapped_device(base_device: &Path) -> Result<MappedDevice> {
    if !base_device.exists() {
        bail!(
            "Base device does not exist at path: {}",
            base_device.display()
        );
    }

    let device_size = blkdev_size(&base_device).context("Could not get block device size")?; // FIXME: Calculate this properly
    let gpt = gpt::disk::read_disk(base_device).context("Could not read GPT from device")?;
    ensure!(
        gpt.partitions().len() == 10,
        "Expected guest device to have 10 partitions but only found {}",
        gpt.partitions().len()
    );

    let data_partition = gpt
        .partitions()
        .get(&10)
        .context("Could not find partition 10")?;

    // let device_size_sectors = 61649264640; // FIXME: Calculate this properly
    let data_partition_len = device_size - Sectors(data_partition.first_lba);

    let dev_mapper = Arc::new(DM::new().context("Failed to create device mapper instance")?);
    cleanup_devices(&dev_mapper);

    let base_device = base_device
        .canonicalize()
        .context("Could not canonicalize base device path")?;

    create_device_for_upgrade(
        dev_mapper,
        base_device,
        Sectors(data_partition.first_lba),
        data_partition_len,
    )
}

/// Creates the mapped device chain.
///
/// We need to create 4 devices (device mapper tables are somewhat primitive, so we stack them):
///   - data_partition_device:
/// TODO
fn create_device_for_upgrade(
    dev_mapper: Arc<DM>,
    base_device: PathBuf,
    data_partition_start: Sectors,
    data_partition_len: Sectors,
) -> Result<MappedDevice> {
    let base_device: devicemapper::Device = devnode_to_devno(&base_device)
        .context("Could not get devno for base device")?
        .context("Base device does not seem to exist")?
        .into();

    LinearDev::setup(
        dev_mapper.as_ref(),
        DmName::new(UPGRADE_DM_NAME).unwrap(),
        None,
        vec![
            TargetLine::new(
                Sectors(0),
                data_partition_start,
                LinearDevTargetParams::Linear(LinearTargetParams::new(base_device, Sectors(0))),
            ),
            TargetLine::new(
                data_partition_start,
                data_partition_len,
                LinearDevTargetParams::Flakey(FlakeyTargetParams::new(
                    base_device,
                    data_partition_start,
                    0,
                    u32::MAX,
                    vec![devicemapper::FeatureArg::DropWrites],
                )),
            ),
        ],
    )
    .context("Could not setup upgrade device")?;

    Ok(MappedDevice {
        name: UPGRADE_DM_NAME,
        path: format!("/dev/mapper/{UPGRADE_DM_NAME}").into(),
        len: Sectors(0),
        dependencies: vec![],
        device_mapper,
    })
    // // Create device for data partition
    // let data_partition_device = MappedDevice::create_linear(
    //     dev_mapper.clone(),
    //     DATA_PARTITION_DM_NAME,
    //     vec![LinearSegment {
    //         source: Box::new(base_device.to_path_buf()),
    //         start: data_partition_start,
    //         len: data_partition_len,
    //     }],
    //     true,
    // )
    // .context("Failed to create data partition device")?;
    //
    // // Create snapshot origin
    // let snapshot_origin = MappedDevice::create_snapshot_origin(
    //     dev_mapper.clone(),
    //     DATA_PARTITION_SNAPSHOT_ORIGIN_NAME,
    //     Box::new(data_partition_device),
    //     true,
    // )
    // .context("Failed to create snapshot origin device")?;
    //
    // // Create snapshot
    // let snapshot_device = MappedDevice::create_snapshot(
    //     dev_mapper.clone(),
    //     DATA_PARTITION_SNAPSHOT_NAME,
    //     snapshot_origin,
    //     CowDevice::new(128 * 1024 * 1024).context("Failed to create COW device")?,
    //     true,
    // )
    // .context("Failed to create snapshot device")?;
    //
    // // Create final upgrade VM device with both segments
    // MappedDevice::create_linear(
    //     dev_mapper,
    //     UPGRADE_DM_NAME,
    //     vec![
    //         // Read-write section: first 9 partitions
    //         LinearSegment {
    //             source: Box::new(base_device.to_path_buf()),
    //             start: Sectors(0),
    //             len: data_partition_start,
    //         },
    //         // Read-only section: snapshot of data partition
    //         LinearSegment {
    //             source: Box::new(snapshot_device),
    //             start: Sectors(0),
    //             len: snapshot_device.len(),
    //         },
    //     ],
    //     false,
    // )
    // .context("Failed to create upgrade device")
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

    for &name in &ALL_DM_NAMES_IN_CLEANUP_ORDER {
        if let Some(existing_name) = existing_devices
            .iter()
            .find(|existing| existing.as_bytes() == name.as_bytes())
        {
            try_remove_device(dev_mapper, existing_name);
        }
    }
}

fn try_remove_device(dev_mapper: &DM, name: &DmName) {
    const MAX_RETRIES: u32 = 10;
    const RETRY_DELAY_SECS: u64 = 5;

    for retry in 1..=MAX_RETRIES {
        match dev_mapper.device_remove(&DevId::Name(name), DmOptions::default()) {
            Ok(_) => return,
            Err(err) => {
                eprintln!(
                    "Failed to remove device {} (attempt {}/{}): {}",
                    name, retry, MAX_RETRIES, err
                );
                if retry < MAX_RETRIES {
                    std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY_SECS));
                }
            }
        }
    }
}
