use crate::device_mapping::{BaseDevice, DeviceTrait, LinearSegment, MappedDevice, TempDevice};
use anyhow::{bail, ensure, Context, Result};
use devicemapper::{DevId, DmName, DmOptions, Sectors, DM};
use std::path::Path;
use std::sync::Arc;

const UPGRADE_DM_NAME: &'static str = "upgrade-guestos";
const DATA_PARTITION_DM_NAME: &'static str = "guestos-data";
const DATA_PARTITION_WRITETHROUGH_DM_NAME: &'static str = "guestos-data-writethrough";

const ALL_DM_NAMES_IN_CLEANUP_ORDER: [&'static str; 3] = [
    // Cleanup order is the reverse of creation order in create_device_for_upgrade.
    UPGRADE_DM_NAME,
    DATA_PARTITION_WRITETHROUGH_DM_NAME,
    DATA_PARTITION_DM_NAME,
];

/// Creates a mapped device for the Upgrade VM which does not persist writes to the data partition.
/// This is done to protect the data partition in case the Upgrade Guest VM wants to write to it.
/// The mapped device has the following structure:
/// 1. GPT + first 9 partitions of base device
/// 2. Data partition that stores writes in a temporary file
/// 3. Backup GPT
pub fn create_mapped_device(base_device: &Path) -> Result<MappedDevice> {
    if !base_device.exists() {
        bail!(
            "Base device does not exist at path: {}",
            base_device.display()
        );
    }

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

    let dev_mapper = Arc::new(DM::new().context("Failed to create device mapper instance")?);
    cleanup_devices(&dev_mapper);

    create_device_for_upgrade(
        dev_mapper,
        BaseDevice::from_path(base_device)?,
        Sectors(data_partition.first_lba),
        Sectors(
            data_partition
                .sectors_len()
                .context("Could not query data_partition len")?,
        ),
    )
}

/// Creates the mapped device chain.
///
/// We create 3 devices (device mapper tables are somewhat primitive, so we stack them):
///   - readonly data partition device:
///         Maps just the data partition of the base device to a readonly device.
///   - cached data partition device:
///         Since the data partition is readonly, writes do not work. We add a cache layer, so
///         writes are still possible but are not persisted to the backing device.
///   - upgrade device:
///         The merger of the base device and the newly created data partition device.
fn create_device_for_upgrade(
    dev_mapper: Arc<DM>,
    base_device: BaseDevice,
    data_partition_start: Sectors,
    data_partition_len: Sectors,
) -> Result<MappedDevice> {
    // Create device for data partition
    let readonly_data_partition_device = MappedDevice::create_linear(
        dev_mapper.clone(),
        DATA_PARTITION_DM_NAME,
        vec![LinearSegment::slice(
            Box::new(base_device),
            data_partition_start,
            data_partition_len,
        )],
        // This is important, by marking it readonly, writes won't be persisted to the data
        // partition
        /*readonly=*/
        true,
    )
    .context("Failed to create data partition device")?;

    // Create cached data partition that writes to the temporary device
    let cached_data_partition_device = MappedDevice::create_writeback_cache(
        dev_mapper.clone(),
        DATA_PARTITION_WRITETHROUGH_DM_NAME,
        Box::new(
            TempDevice::new(Sectors(16 * 1024))
                .context("Failed to create temporary device for metadata")?,
        ),
        Box::new(
            TempDevice::new(Sectors(1024 * 1024))
                .context("Failed to create temporary device for cache")?,
        ),
        Box::new(readonly_data_partition_device),
        /*readonly=*/ false,
    )
    .context("Failed to create cached data partition device")?;

    // Create final upgrade VM device with all segments
    MappedDevice::create_linear(
        dev_mapper,
        UPGRADE_DM_NAME,
        vec![
            // Read-write section: GPT + first 9 partitions
            LinearSegment::prefix(Box::new(base_device), data_partition_start),
            // Read-only section: data partition
            LinearSegment::full(Box::new(cached_data_partition_device)),
            // Read-write section: whatever is left at the end of the device (backup GPT)
            LinearSegment::suffix(
                Box::new(base_device),
                data_partition_start + data_partition_len,
            ),
        ],
        /*readonly=*/ false,
    )
    .context("Failed to create upgrade device")
}

fn cleanup_devices(dev_mapper: &DM) {
    let devices = match dev_mapper.list_devices() {
        Ok(devices) => devices,
        Err(err) => {
            eprintln!("Failed to list devices: {}", err);
            return;
        }
    };

    for &name in &ALL_DM_NAMES_IN_CLEANUP_ORDER {
        for existing_device in &devices {
            if existing_device.0.as_bytes() == name.as_bytes() {
                try_remove_device(dev_mapper, &existing_device.0);
            }
        }
    }
}

fn try_remove_device(dev_mapper: &DM, name: &DmName) {
    const MAX_RETRIES: u32 = 10;
    const RETRY_DELAY_SECS: u64 = 2;

    for retry in 1..=MAX_RETRIES {
        match dev_mapper.device_remove(&DevId::Name(name), DmOptions::default()) {
            Ok(_) => return,
            Err(err) => {
                eprintln!("Failed to remove device {name} (attempt {retry}/{MAX_RETRIES}): {err}");
                if retry < MAX_RETRIES {
                    std::thread::sleep(std::time::Duration::from_secs(RETRY_DELAY_SECS));
                }
            }
        }
    }
}
